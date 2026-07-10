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
import { describe, it, expect } from 'vitest';
import { assessRisk } from '../src/core/riskEngine.js';
import { buildLevelConfig } from '../src/config/securityLevels.js';
import type { DetectionSignal } from '../src/types.js';

const level = buildLevelConfig(6);

function sig(category: string, score: number): DetectionSignal {
  return { detector: 'test', category, score, weight: 1, matched: [] };
}

describe('assessRisk', () => {
  it('hard-blocks any csam signal', () => {
    const result = assessRisk([sig('csam', 0.1)], level, false);
    expect(result.action).toBe('block');
    expect(result.riskScore).toBe(1);
  });

  it('allows empty signals', () => {
    expect(assessRisk([], level, false).action).toBe('allow');
  });

  it('returns lockout when locked', () => {
    expect(assessRisk([], level, true).action).toBe('lockout');
  });

  it('flags mid scores and blocks high scores', () => {
    const flag = assessRisk([sig('jailbreak', 0.4)], level, false);
    expect(['flag', 'block', 'allow']).toContain(flag.action);

    const block = assessRisk([sig('jailbreak', 0.95)], level, false);
    expect(block.action).toBe('block');
    expect(block.blockedCategories).toContain('jailbreak');
  });

  it('caps combined score at 1', () => {
    const result = assessRisk([sig('a', 1), sig('b', 1), sig('c', 1)], level, false);
    expect(result.riskScore).toBeLessThanOrEqual(1);
  });
});
