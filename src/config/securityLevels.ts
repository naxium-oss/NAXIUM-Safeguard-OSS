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
import type { SecurityLevel } from '../types.js';

export interface LevelConfig {
  level: SecurityLevel;
  blockThreshold: number;
  flagThreshold: number;
  enableObfuscationDecoding: boolean;
  enableSemanticSimilarity: boolean;
  enableStrictPII: boolean;
  enableToolStrictMode: boolean;
  maxViolationsBeforeLockout: number;
  lockoutDurationMs: number;
  rateLimitPerMinute: number;
}

function clamp01(n: number): number {
  return Math.max(0, Math.min(1, n));
}

/**
 * Deterministically derives strictness from a 0-10 slider.
 *
 * Level 0  = heuristic scoring effectively disabled (thresholds near-unreachable).
 *            NOTE: the CSAM hard-block category in riskEngine.ts is NOT
 *            controlled by this config and cannot be disabled at any level.
 *            This is an intentional, documented, non-negotiable exception —
 *            not a hidden behavior.
 * Level 10 = maximum strictness. Expect false positives on legitimate
 *            edge-case content (security research, fiction, medical, etc).
 */
export function buildLevelConfig(level: SecurityLevel): LevelConfig {
  const t = level / 10;

  return {
    level,
    blockThreshold: clamp01(0.9 - t * 0.65), // 0.90 -> 0.25
    flagThreshold: clamp01(0.6 - t * 0.48), // 0.60 -> 0.12
    enableObfuscationDecoding: level >= 2,
    enableSemanticSimilarity: level >= 4,
    enableStrictPII: level >= 5,
    enableToolStrictMode: level >= 3,
    maxViolationsBeforeLockout: Math.max(1, Math.round(10 - t * 8)), // 10 -> 2
    lockoutDurationMs: level === 0 ? 0 : Math.round(60_000 + t * 14 * 60_000), // up to 15min
    rateLimitPerMinute: Math.max(5, Math.round(300 - t * 290)), // 300/min -> 10/min
  };
}
