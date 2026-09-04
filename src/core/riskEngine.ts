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
import type { DetectionSignal, GuardAction, StanceAssessment } from '../types.js';
import type { LevelConfig } from '../config/securityLevels.js';

export interface RiskAssessment {
  riskScore: number;
  action: GuardAction;
  blockedCategories: string[];
  /** Aggregated evidence groups, strongest first — useful for debugging. */
  evidence: EvidenceGroup[];
}

export interface EvidenceGroup {
  detector: string;
  category: string;
  score: number;
  tier: 'primary' | 'corroborating';
  hits: number;
}

export interface RiskContext {
  stance?: StanceAssessment;
  /** Extra risk carried over from earlier turns of the same session. */
  sessionRisk?: number;
  /** Per-category multipliers from user config. */
  categoryWeights?: Record<string, number>;
}

// Non-negotiable, not controlled by securityLevel. See docs/LIMITATIONS.md.
const HARD_BLOCK_CATEGORIES = new Set(['csam']);

/**
 * Categories that describe *subject matter* rather than intent. A defensive,
 * educational or fictional request that merely mentions these is discounted;
 * jailbreak, exfiltration and hard-harm categories are never discounted.
 */
const DAMPENABLE_CATEGORIES = new Set([
  'cyberattack',
  'high_signal_token',
  'ngram_risk',
  'fuzzy_attack_vocab',
  'dual_use_recon',
  'attack_modifier',
  'kill_chain_planning',
  'social_engineering',
  'privacy_invasion',
  'fraud',
  'dangerous_shell_command',
  'exfiltration_destination',
  'drug_synthesis',
]);

/** How much each stance discounts dampenable evidence at full confidence. */
const STANCE_DISCOUNT: Record<StanceAssessment['stance'], number> = {
  defensive: 0.7,
  informational: 0.55,
  creative: 0.3,
  operational: 0,
  unknown: 0,
};

/** Decay applied to each successive independent primary detector. */
const PRIMARY_DECAY = 0.45;
/** First corroborating group's contribution when a primary signal exists. */
const CORROBORATION_WITH_PRIMARY = 0.35;
/** First corroborating group's contribution with no primary signal at all. */
const CORROBORATION_ALONE = 0.6;
const CORROBORATION_DECAY = 0.4;
/** Evasive variants are real hits, but scored slightly below canonical ones. */
const VARIANT_PENALTY = 0.92;

function clamp01(n: number): number {
  return Math.max(0, Math.min(1, n));
}

function tierOf(signal: DetectionSignal): 'primary' | 'corroborating' {
  return signal.tier ?? 'primary';
}

function effectiveScore(signal: DetectionSignal, ctx: RiskContext): number {
  const reliability = signal.reliability ?? 1;
  const variantFactor = signal.variant && signal.variant !== 'canonical' ? VARIANT_PENALTY : 1;
  const categoryWeight = ctx.categoryWeights?.[signal.category] ?? 1;
  let score = signal.score * signal.weight * reliability * variantFactor * categoryWeight;

  const stance = ctx.stance;
  if (stance && DAMPENABLE_CATEGORIES.has(signal.category)) {
    const discount = STANCE_DISCOUNT[stance.stance] * stance.confidence;
    score *= 1 - clamp01(discount);
  }

  return clamp01(score);
}

/**
 * Collapse signals into one group per detector+category.
 *
 * Variant rescans and overlapping regexes routinely report the same finding
 * many times; without collapsing, a single lexicon hit could stack itself past
 * the block threshold. Repeat hits inside a group add a small bonus only.
 */
function groupSignals(signals: DetectionSignal[], ctx: RiskContext): EvidenceGroup[] {
  const groups = new Map<string, EvidenceGroup & { second: number }>();

  for (const signal of signals) {
    const score = effectiveScore(signal, ctx);
    if (score <= 0) continue;
    const key = `${signal.detector}|${signal.category}`;
    const existing = groups.get(key);
    if (!existing) {
      groups.set(key, {
        detector: signal.detector,
        category: signal.category,
        score,
        second: 0,
        tier: tierOf(signal),
        hits: 1,
      });
      continue;
    }
    existing.hits += 1;
    if (score > existing.score) {
      existing.second = existing.score;
      existing.score = score;
    } else if (score > existing.second) {
      existing.second = score;
    }
    // A group is primary if any of its members is.
    if (tierOf(signal) === 'primary') existing.tier = 'primary';
  }

  return [...groups.values()]
    .map(({ second, ...group }) => ({
      ...group,
      score: clamp01(group.score + second * 0.15),
    }))
    .sort((a, b) => b.score - a.score);
}

/**
 * Score signals and pick an action.
 *
 * Independent detectors corroborate with diminishing returns, repeats of the
 * same detector do not, and evidence that is corroborating-only stays below the
 * block threshold by construction so weak vocabulary overlap can flag but never
 * block. `csam` is the one category that ignores all of this.
 */
export function assessRisk(
  signals: DetectionSignal[],
  level: LevelConfig,
  isLockedOut: boolean,
  context: RiskContext = {},
): RiskAssessment {
  if (isLockedOut) {
    return {
      riskScore: 1,
      action: 'lockout',
      blockedCategories: ['brute_force_lockout'],
      evidence: [],
    };
  }

  const hardBlocked = signals.filter((s) => HARD_BLOCK_CATEGORIES.has(s.category));
  if (hardBlocked.length > 0) {
    return {
      riskScore: 1,
      action: 'block',
      blockedCategories: [...new Set(hardBlocked.map((s) => s.category))],
      evidence: [],
    };
  }

  if (signals.length === 0) {
    return { riskScore: 0, action: 'allow', blockedCategories: [], evidence: [] };
  }

  const stanceContext: RiskContext = {
    ...context,
    stance: context.stance ? scaleStance(context.stance, level.stanceDampening) : undefined,
  };
  const groups = groupSignals(signals, stanceContext);
  const primary = groups.filter((g) => g.tier === 'primary');
  const corroborating = groups.filter((g) => g.tier === 'corroborating');

  let riskScore = 0;
  let factor = 1;
  for (const group of primary) {
    riskScore += group.score * factor;
    factor *= PRIMARY_DECAY;
  }

  let corroborationFactor = primary.length > 0 ? CORROBORATION_WITH_PRIMARY : CORROBORATION_ALONE;
  for (const group of corroborating) {
    riskScore += group.score * corroborationFactor;
    corroborationFactor *= CORROBORATION_DECAY;
  }

  if (context.sessionRisk && context.sessionRisk > 0 && groups.length > 0) {
    riskScore += context.sessionRisk * level.sessionRiskWeight;
  }

  riskScore = clamp01(riskScore);

  // Weak, unsupported evidence may flag for review but must not hard-block.
  if (primary.length === 0) {
    riskScore = Math.min(riskScore, Math.max(0, level.blockThreshold - 0.01));
  }

  let action: GuardAction = 'allow';
  if (riskScore >= level.blockThreshold) action = 'block';
  else if (riskScore >= level.flagThreshold) action = 'flag';

  const blockedCategories =
    action === 'block'
      ? [...new Set(groups.filter((g) => g.score >= 0.25).map((g) => g.category))]
      : [];

  return { riskScore, action, blockedCategories, evidence: groups };
}

/** Higher security levels trust benign framing less. */
function scaleStance(stance: StanceAssessment, dampening: number): StanceAssessment {
  return { ...stance, confidence: clamp01(stance.confidence * dampening) };
}
