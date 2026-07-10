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
import type { GuardContext, GuardResult, ToolCallGuardInput, DetectionSignal, SecurityLevel } from '../types.js';
import { detectPatterns } from '../detectors/patternDetector.js';
import { normalizeUnicode, deLeet, extractDecodedVariants } from '../detectors/obfuscationNormalizer.js';
import { detectPII } from '../detectors/piiDetector.js';
import { classifyTopics } from '../detectors/topicClassifier.js';
import { semanticSimilarityCheck } from '../detectors/semanticSimilarity.js';
import { detectJailbreakIntent } from '../detectors/intentHeuristicDetector.js';
import { detectInnocentDisguise } from '../detectors/disguiseDetector.js';
import { detectAuthorityLaundering } from '../detectors/authorityLaunderingDetector.js';
import { detectDestructiveCommands } from '../detectors/destructiveCommandDetector.js';
import { detectHighSignalTokens } from '../detectors/highSignalTokenDetector.js';
import { detectNgramRisk } from '../detectors/ngramRiskDetector.js';
import { detectStructuralAnomalies } from '../detectors/structuralAnomalyDetector.js';
import { detectFuzzyTokens } from '../detectors/fuzzyTokenDetector.js';
import { detectAttackVerbChain } from '../detectors/attackVerbChainDetector.js';
import { detectCodeSmuggling } from '../detectors/codeSmuggleDetector.js';
import { detectSlotFill } from '../detectors/slotFillDetector.js';
import { detectUrlThreats } from '../detectors/urlThreatDetector.js';
import { detectRepetitionBomb } from '../detectors/repetitionBombDetector.js';
import { scanForSecrets } from '../detectors/secretsScanner.js';
import { detectCredentialDumps } from '../detectors/credentialDumpDetector.js';
import { detectExfiltration } from '../detectors/exfiltrationDetector.js';
import { validateToolCall } from '../detectors/toolCallValidator.js';
import { RateLimiter } from '../protection/rateLimiter.js';
import { BruteForceGuard } from '../protection/bruteForceGuard.js';
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
    return this.runGuarded('input', text, context, (normalized) => {
      const signals: DetectionSignal[] = [];
      signals.push(...detectPatterns(normalized));
      signals.push(...detectPatterns(deLeet(normalized)));
      signals.push(...detectJailbreakIntent(normalized));
      signals.push(...detectInnocentDisguise(normalized));
      signals.push(...detectAuthorityLaundering(normalized));
      signals.push(...detectDestructiveCommands(normalized));
      signals.push(...detectHighSignalTokens(normalized));
      signals.push(...detectFuzzyTokens(normalized));
      signals.push(...detectNgramRisk(normalized));
      signals.push(...detectStructuralAnomalies(normalized));
      signals.push(...detectAttackVerbChain(normalized));
      signals.push(...detectCodeSmuggling(normalized));
      signals.push(...detectSlotFill(normalized));
      signals.push(...detectUrlThreats(normalized));
      signals.push(...detectRepetitionBomb(normalized));
      signals.push(...detectPII(normalized, this.levelConfig.enableStrictPII));
      signals.push(...classifyTopics(normalized));
      signals.push(...scanForSecrets(normalized));
      signals.push(...detectCredentialDumps(normalized));
      signals.push(...detectExfiltration(normalized));

      if (this.levelConfig.enableObfuscationDecoding) {
        for (const variant of extractDecodedVariants(normalized)) {
          const vSignals = [
            ...detectPatterns(variant),
            ...detectJailbreakIntent(variant),
            ...detectInnocentDisguise(variant),
            ...detectAuthorityLaundering(variant),
            ...detectDestructiveCommands(variant),
            ...detectHighSignalTokens(variant),
            ...detectFuzzyTokens(variant),
            ...detectNgramRisk(variant),
            ...detectStructuralAnomalies(variant),
            ...detectAttackVerbChain(variant),
            ...detectCodeSmuggling(variant),
            ...detectSlotFill(variant),
            ...detectUrlThreats(variant),
            ...detectRepetitionBomb(variant),
            ...classifyTopics(variant),
            ...scanForSecrets(variant),
            ...detectCredentialDumps(variant),
            ...detectExfiltration(variant),
          ];
          if (vSignals.length > 0) {
            signals.push({
              detector: 'obfuscationNormalizer',
              category: 'obfuscation_evasion',
              score: 0.6,
              weight: 1,
              matched: [variant.slice(0, 60)],
            });
            signals.push(...vSignals);
          }
        }
      }

      if (this.levelConfig.enableSemanticSimilarity) {
        // Slightly lower threshold so paraphrases of known attacks surface
        // even when exact regexes miss — intentHeuristic covers the rest.
        signals.push(...semanticSimilarityCheck(normalized, 0.36));
      }

      return signals;
    });
  }

  guardOutput(text: string, context: GuardContext = {}): GuardResult {
    return this.runGuarded('output', text, context, (normalized) => {
      const signals: DetectionSignal[] = [
        ...scanForSecrets(normalized),
        ...detectCredentialDumps(normalized),
        ...detectExfiltration(normalized),
        ...detectPII(normalized, this.levelConfig.enableStrictPII),
        ...classifyTopics(normalized),
        ...detectPatterns(normalized).filter(
          (s) => s.category === 'system_prompt_extraction' || s.category === 'encoding_trick_hint',
        ),
      ];

      if (this.levelConfig.enableObfuscationDecoding) {
        for (const variant of extractDecodedVariants(normalized)) {
          const vSignals = [
            ...scanForSecrets(variant),
            ...detectCredentialDumps(variant),
            ...classifyTopics(variant),
            ...detectPatterns(variant).filter((s) => s.category === 'system_prompt_extraction'),
          ];
          if (vSignals.length > 0) {
            signals.push({
              detector: 'obfuscationNormalizer',
              category: 'obfuscation_evasion',
              score: 0.55,
              weight: 1,
              matched: [variant.slice(0, 60)],
            });
            signals.push(...vSignals);
          }
        }
      }

      return signals;
    });
  }

  guardToolCall(input: ToolCallGuardInput, context: GuardContext = {}): GuardResult {
    const serialized = JSON.stringify(input);
    return this.runGuarded('tool', serialized, context, () =>
      validateToolCall(input, this.levelConfig.enableToolStrictMode),
    );
  }

  resetSession(sessionKey: string): void {
    this.bruteForce.reset(sessionKey);
    this.rateLimiter.reset(sessionKey);
  }

  private runGuarded(
    channel: Channel,
    originalText: string,
    context: GuardContext,
    collect: (normalized: string) => DetectionSignal[],
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

    // Reject oversized payloads instead of scanning a prefix (suffix-bypass)
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

    const normalized = channel === 'tool' ? originalText : normalizeUnicode(originalText);
    const signals = channel === 'tool' ? collect(originalText) : collect(normalized);
    return this.processResult(signals, start, originalText, context, channel, key);
  }

  private processResult(
    signals: DetectionSignal[],
    start: number,
    originalText: string,
    context: GuardContext,
    channel: Channel,
    key: string,
  ): GuardResult {
    const isLockedOut = this.bruteForce.isLockedOut(key);
    const assessment = assessRisk(signals, this.levelConfig, isLockedOut);

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
            // Never log raw protectionKey / full IP in default path beyond truncated
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
    // Avoid logging raw secret material
    return preview.replace(/[A-Za-z0-9_-]{20,}/g, '***');
  }
  return preview;
}
