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
import type { DetectionSignal, GuardAction } from '../types.js';
import type { LevelConfig } from '../config/securityLevels.js';

export interface RiskAssessment {
  riskScore: number;
  action: GuardAction;
  blockedCategories: string[];
}

// Non-negotiable, not controlled by securityLevel. See docs/LIMITATIONS.md.
const HARD_BLOCK_CATEGORIES = new Set(['csam']);

export function assessRisk(
  signals: DetectionSignal[],
  level: LevelConfig,
  isLockedOut: boolean,
): RiskAssessment {
  if (isLockedOut) {
    return { riskScore: 1, action: 'lockout', blockedCategories: ['brute_force_lockout'] };
  }

  // Any CSAM category signal hard-blocks regardless of score magnitude.
  const hardBlocked = signals.filter((s) => HARD_BLOCK_CATEGORIES.has(s.category));
  if (hardBlocked.length > 0) {
    return { riskScore: 1, action: 'block', blockedCategories: [...new Set(hardBlocked.map((s) => s.category))] };
  }

  if (signals.length === 0) {
    return { riskScore: 0, action: 'allow', blockedCategories: [] };
  }

  // Dominant signal contributes fully, each corroborating signal adds
  // diminishing weight (avoids naive summation blowing past 1.0 too easily).
  const sorted = [...signals].sort((a, b) => b.score * b.weight - a.score * a.weight);
  let riskScore = 0;
  let contribution = 1;
  for (const s of sorted) {
    riskScore += s.score * s.weight * contribution;
    contribution *= 0.5;
  }
  riskScore = Math.min(1, riskScore);

  let action: GuardAction = 'allow';
  if (riskScore >= level.blockThreshold) action = 'block';
  else if (riskScore >= level.flagThreshold) action = 'flag';

  const blockedCategories =
    action === 'block' ? [...new Set(sorted.filter((s) => s.score >= 0.3).map((s) => s.category))] : [];

  return { riskScore, action, blockedCategories };
}
