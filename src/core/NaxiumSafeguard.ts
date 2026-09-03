/**
 * Copyright 2026 enderchefcoder
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { DEFAULT_CONFIG, type NaxiumConfig } from '../config/defaultConfig.js';
import { buildLevelConfig, type LevelConfig } from '../config/securityLevels.js';
import type {
  GuardContext,
  GuardResult,
  ToolCallGuardInput,
  DetectionSignal,
  SecurityLevel,
  StanceAssessment,
} from '../types.js';
import { buildVariants } from '../detectors/obfuscationNormalizer.js';
import { analyzeStance } from '../detectors/stanceAnalyzer.js';
import { scanWithVariants, scanOutputWithVariants } from '../detectors/detectorPipeline.js';
import { validateToolCall } from '../detectors/toolCallValidator.js';
import { RateLimiter } from '../protection/rateLimiter.js';
import { BruteForceGuard } from '../protection/bruteForceGuard.js';
import { SessionRiskTracker } from '../protection/sessionRiskTracker.js';
import { assessRisk } from './riskEngine.js';
import { wipeMessage, buildAlert } from './sanitizer.js';
import { logEvent } from '../utils/logger.js';
import { parseSecurityLevel } from '../utils/parseSecurityLevel.js';
import { deepMerge } from '../utils/deepMerge.js';

type Channel = 'input' | 'output' | 'tool';

/** Hard cap for library callers (HTTP Zod already enforces 65KB). */
const MAX_TEXT_CHARS = 65_536;

export class NaxiumSafeguard {
  private config: NaxiumConfig;
  private levelConfig: LevelConfig;
  private rateLimiter: RateLimiter;
  private bruteForce: BruteForceGuard;
  private sessionRisk: SessionRiskTracker;

  constructor(userConfig: Partial<NaxiumConfig> = {}) {
    const level = parseSecurityLevel(userConfig.securityLevel ?? DEFAULT_CONFIG.securityLevel);
    this.config = deepMerge(
      DEFAULT_CONFIG as unknown as Record<string, unknown>,
      { ...userConfig, securityLevel: level } as unknown as Record<string, unknown>,
    ) as unknown as NaxiumConfig;
    this.levelConfig = buildLevelConfig(this.config.securityLevel);
    this.rateLimiter = new RateLimiter(this.levelConfig.rateLimitPerMinute);
    this.bruteForce = new BruteForceGuard(
      this.levelConfig.maxViolationsBeforeLockout,
      this.levelConfig.lockoutDurationMs,
    );
    this.sessionRisk = new SessionRiskTracker();
  }

  setSecurityLevel(level: SecurityLevel): void {
    const parsed = parseSecurityLevel(level, this.config.securityLevel);
    this.config.securityLevel = parsed;
    this.levelConfig = buildLevelConfig(parsed);
    this.rateLimiter.setLimit(this.levelConfig.rateLimitPerMinute);
    this.bruteForce.configure(this.levelConfig.maxViolationsBeforeLockout, this.levelConfig.lockoutDurationMs);
  }

  getSecurityLevel(): SecurityLevel {
    return this.config.securityLevel;
  }

  guardInput(text: string, context: GuardContext = {}): GuardResult {
    return this.runGuarded('input', text, context, (normalized, original) => {
      const stance = analyzeStance(original);
      const variants = buildVariants(original, {
        decode: this.levelConfig.enableObfuscationDecoding,
      });
      const signals = scanWithVariants(normalized, variants, {
        level: this.levelConfig,
        strictPii: this.levelConfig.enableStrictPII,
      });
      return { signals, stance };
    });
  }

  guardOutput(text: string, context: GuardContext = {}): GuardResult {
    return this.runGuarded('output', text, context, (normalized, original) => {
      const variants = buildVariants(original, {
        decode: this.levelConfig.enableObfuscationDecoding,
      });
      const signals = scanOutputWithVariants(normalized, variants, {
        level: this.levelConfig,
        strictPii: this.levelConfig.enableStrictPII,
      });
      return { signals };
    });
  }

  guardToolCall(input: ToolCallGuardInput, context: GuardContext = {}): GuardResult {
    const serialized = JSON.stringify(input);
    return this.runGuarded('tool', serialized, context, () => ({
      signals: validateToolCall(input, this.levelConfig.enableToolStrictMode),
    }));
  }

  resetSession(sessionKey: string): void {
    this.bruteForce.reset(sessionKey);
    this.rateLimiter.reset(sessionKey);
    this.sessionRisk.reset(sessionKey);
  }

  private runGuarded(
    channel: Channel,
    originalText: string,
    context: GuardContext,
    collect: (
      normalized: string,
      original: string,
    ) => { signals: DetectionSignal[]; stance?: StanceAssessment },
  ): GuardResult {
    const start = performance.now();
    const key = this.rateKey(context);

    if (this.bruteForce.isLockedOut(key)) {
      return this.finalize([], 'lockout', 1, start, originalText, context, channel);
    }

    const rl = this.rateLimiter.check(key);
    if (!rl.allowed) {
      return this.finalize(
        [{ detector: 'rateLimiter', category: 'rate_limit_exceeded', score: 1, weight: 1, matched: [] }],
        'block',
        1,
        start,
        originalText,
        context,
        channel,
        ['rate_limit_exceeded'],
      );
    }

    if (originalText.length > MAX_TEXT_CHARS) {
      return this.finalize(
        [
          {
            detector: 'naxium',
            category: 'payload_too_large',
            score: 1,
            weight: 1,
            matched: [`${originalText.length}>${MAX_TEXT_CHARS}`],
          },
        ],
        'block',
        1,
        start,
        originalText,
        context,
        channel,
        ['payload_too_large'],
      );
    }

    if (channel === 'tool') {
      const { signals } = collect(originalText, originalText);
      return this.processResult(signals, start, originalText, context, channel, key);
    }

    const normalized = buildVariants(originalText, { decode: false })[0]?.text ?? originalText;
    const { signals, stance } = collect(normalized, originalText);
    return this.processResult(signals, start, originalText, context, channel, key, stance);
  }

  private processResult(
    signals: DetectionSignal[],
    start: number,
    originalText: string,
    context: GuardContext,
    channel: Channel,
    key: string,
    stance?: StanceAssessment,
  ): GuardResult {
    const isLockedOut = this.bruteForce.isLockedOut(key);
    const carried = this.levelConfig.enableSessionTracking ? this.sessionRisk.getRisk(key) : 0;

    const assessment = assessRisk(signals, this.levelConfig, isLockedOut, {
      stance: channel === 'input' ? stance : undefined,
      sessionRisk: carried,
      categoryWeights: this.config.categoryWeights,
    });

    if (this.levelConfig.enableSessionTracking && assessment.riskScore > 0) {
      this.sessionRisk.record(
        key,
        signals.map((s) => s.category),
        assessment.riskScore,
      );
    }

    if (assessment.action === 'block' || assessment.action === 'lockout') {
      this.bruteForce.recordViolation(key);
    }

    return this.finalize(
      signals,
      assessment.action,
      assessment.riskScore,
      start,
      originalText,
      context,
      channel,
      assessment.blockedCategories,
      stance,
    );
  }

  private finalize(
    signals: DetectionSignal[],
    action: GuardResult['action'],
    riskScore: number,
    start: number,
    originalText: string,
    context: GuardContext,
    channel: Channel,
    blockedCategories: string[] = [],
    stance?: StanceAssessment,
  ): GuardResult {
    const safe = action === 'allow' || action === 'flag';
    const templateKey = channel === 'tool' ? 'toolCall' : channel;

    let alertMessage: string | undefined;
    let sanitizedText: string | undefined;

    if (action === 'block') {
      alertMessage = buildAlert(this.config.alertMessage[templateKey as 'input' | 'output' | 'toolCall'], blockedCategories);
      sanitizedText = this.config.wipeOnBlock ? wipeMessage() : undefined;
    } else if (action === 'lockout') {
      alertMessage = this.config.alertMessage.lockout;
      sanitizedText = this.config.wipeOnBlock ? wipeMessage() : undefined;
    }

    const result: GuardResult = {
      safe,
      action,
      riskScore,
      threshold: this.levelConfig.blockThreshold,
      signals,
      sanitizedText,
      alertMessage,
      blockedCategories,
      latencyMs: performance.now() - start,
      stance: channel === 'input' ? stance : undefined,
    };

    if (this.config.logging.enabled && (!safe || this.config.logging.logSafeRequests)) {
      void logEvent(
        {
          timestamp: new Date().toISOString(),
          channel,
          action,
          riskScore,
          blockedCategories,
          context: {
            userId: context.userId,
            sessionId: context.sessionId,
            ip: context.ip ? truncate(context.ip, 64) : undefined,
          },
          textPreview: redactPreview(originalText, channel),
          signalSummary: signals.map((s) => ({ detector: s.detector, category: s.category, score: s.score })),
        },
        this.config.logging.logPath,
      );
    }

    return result;
  }

  private rateKey(context: GuardContext): string {
    if (context.protectionKey && context.protectionKey.length > 0) {
      return context.protectionKey;
    }
    return context.sessionId ?? context.userId ?? context.ip ?? 'global';
  }
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max)}…`;
}

function redactPreview(text: string, channel: Channel): string {
  const preview = text.slice(0, 120);
  if (channel === 'output' || channel === 'input') {
    return preview.replace(/[A-Za-z0-9_-]{20,}/g, '***');
  }
  return preview;
}
