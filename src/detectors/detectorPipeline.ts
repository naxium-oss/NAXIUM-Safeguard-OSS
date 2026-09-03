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
import type { DetectionSignal } from '../types.js';
import type { LevelConfig } from '../config/securityLevels.js';
import type { TextVariant } from './obfuscationNormalizer.js';
import { detectPatterns } from './patternDetector.js';
import { detectJailbreakIntent } from './intentHeuristicDetector.js';
import { detectInnocentDisguise } from './disguiseDetector.js';
import { detectAuthorityLaundering } from './authorityLaunderingDetector.js';
import { detectDestructiveCommands } from './destructiveCommandDetector.js';
import { detectHighSignalTokens } from './highSignalTokenDetector.js';
import { detectFuzzyTokens } from './fuzzyTokenDetector.js';
import { detectNgramRisk } from './ngramRiskDetector.js';
import { detectStructuralAnomalies } from './structuralAnomalyDetector.js';
import { detectAttackVerbChain } from './attackVerbChainDetector.js';
import { detectCodeSmuggling } from './codeSmuggleDetector.js';
import { detectSlotFill } from './slotFillDetector.js';
import { detectUrlThreats } from './urlThreatDetector.js';
import { detectRepetitionBomb } from './repetitionBombDetector.js';
import { detectPII } from './piiDetector.js';
import { classifyTopics } from './topicClassifier.js';
import { scanForSecrets } from './secretsScanner.js';
import { detectCredentialDumps } from './credentialDumpDetector.js';
import { detectExfiltration } from './exfiltrationDetector.js';
import { semanticSimilarityCheck } from './semanticSimilarity.js';
import { detectMultilingualIntent } from './multilingualIntentDetector.js';
import { detectConfigInjection } from './configInjectionDetector.js';
import { detectPromptMarkers } from './promptMarkerDetector.js';
import { detectPayloadSplit } from './payloadSplitDetector.js';
import { detectStatisticalIntent } from './statisticalIntentDetector.js';
import { detectOutputCompliance } from './outputComplianceDetector.js';

export type DetectorChannel = 'input' | 'output' | 'variant';

type DetectorFn = (text: string) => DetectionSignal[];

function tagVariant(signals: DetectionSignal[], variant: TextVariant): DetectionSignal[] {
  return signals.map((s) => ({
    ...s,
    variant: variant.label,
    // Evasive reconstructions are slightly less certain than canonical hits.
    score: variant.evasive && s.tier !== 'corroborating' ? s.score * 0.95 : s.score,
  }));
}

const INPUT_DETECTORS: DetectorFn[] = [
  detectPatterns,
  detectJailbreakIntent,
  detectInnocentDisguise,
  detectAuthorityLaundering,
  detectDestructiveCommands,
  detectHighSignalTokens,
  detectFuzzyTokens,
  detectNgramRisk,
  detectStructuralAnomalies,
  detectAttackVerbChain,
  detectCodeSmuggling,
  detectSlotFill,
  detectUrlThreats,
  detectRepetitionBomb,
  detectConfigInjection,
  detectPromptMarkers,
  detectPayloadSplit,
];

const VARIANT_DETECTORS: DetectorFn[] = [
  detectPatterns,
  detectJailbreakIntent,
  detectInnocentDisguise,
  detectAuthorityLaundering,
  detectDestructiveCommands,
  detectHighSignalTokens,
  detectFuzzyTokens,
  detectNgramRisk,
  detectStructuralAnomalies,
  detectAttackVerbChain,
  detectCodeSmuggling,
  detectSlotFill,
  detectUrlThreats,
  detectRepetitionBomb,
  classifyTopics,
  scanForSecrets,
  detectCredentialDumps,
  detectExfiltration,
  detectConfigInjection,
  detectPromptMarkers,
  detectPayloadSplit,
];

export interface ScanOptions {
  level: LevelConfig;
  channel: DetectorChannel;
  strictPii: boolean;
  variants?: TextVariant[];
}

/** Run the detector stack for one normalized text slice. */
export function scanText(text: string, options: ScanOptions): DetectionSignal[] {
  const signals: DetectionSignal[] = [];

  if (options.channel === 'input' || options.channel === 'variant') {
    for (const run of options.channel === 'variant' ? VARIANT_DETECTORS : INPUT_DETECTORS) {
      signals.push(...run(text));
    }
  }

  if (options.channel === 'input') {
    signals.push(...detectPII(text, options.strictPii));
    signals.push(...classifyTopics(text));
    signals.push(...scanForSecrets(text));
    signals.push(...detectCredentialDumps(text));
    signals.push(...detectExfiltration(text));

    if (options.level.enableMultilingualIntent) {
      signals.push(...detectMultilingualIntent(text));
    }
    if (options.level.enableStatisticalIntent) {
      signals.push(...detectStatisticalIntent(text));
    }
    if (options.level.enableSemanticSimilarity) {
      signals.push(...semanticSimilarityCheck(text, 0.36));
    }
  }

  if (options.channel === 'output') {
    signals.push(...scanForSecrets(text));
    signals.push(...detectCredentialDumps(text));
    signals.push(...detectExfiltration(text));
    signals.push(...detectPII(text, options.strictPii));
    signals.push(...classifyTopics(text));
    signals.push(...detectOutputCompliance(text));
    signals.push(
      ...detectPatterns(text).filter(
        (s) =>
          s.category === 'system_prompt_extraction' ||
          s.category === 'encoding_trick_hint' ||
          s.category === 'prompt_injection_marker',
      ),
    );
  }

  return signals;
}

/** Scan canonical text plus any derived variants, deduping by label. */
export function scanWithVariants(
  canonical: string,
  variants: TextVariant[],
  options: Omit<ScanOptions, 'channel' | 'variants'>,
): DetectionSignal[] {
  const signals = scanText(canonical, { ...options, channel: 'input' });

  for (const variant of variants) {
    if (variant.label === 'canonical') continue;
    const vSignals = scanText(variant.text, { ...options, channel: 'variant' });
    if (vSignals.length === 0) continue;

    if (variant.evasive) {
      signals.push({
        detector: 'obfuscationNormalizer',
        category: 'obfuscation_evasion',
        score: 0.55,
        weight: 1,
        tier: 'corroborating',
        reliability: 0.85,
        variant: variant.label,
        matched: [variant.text.slice(0, 60)],
        details: `Risk surfaced only in ${variant.label} variant`,
      });
    }

    signals.push(...tagVariant(vSignals, variant));
  }

  return signals;
}

export function scanOutputWithVariants(
  canonical: string,
  variants: TextVariant[],
  options: Omit<ScanOptions, 'channel' | 'variants'>,
): DetectionSignal[] {
  const signals = scanText(canonical, { ...options, channel: 'output' });

  for (const variant of variants) {
    if (variant.label === 'canonical') continue;
    const vSignals = scanText(variant.text, { ...options, channel: 'output' });
    if (vSignals.length === 0) continue;
    if (variant.evasive) {
      signals.push({
        detector: 'obfuscationNormalizer',
        category: 'obfuscation_evasion',
        score: 0.5,
        weight: 1,
        tier: 'corroborating',
        variant: variant.label,
        matched: [variant.text.slice(0, 60)],
      });
    }
    signals.push(...tagVariant(vSignals, variant));
  }

  return signals;
}
