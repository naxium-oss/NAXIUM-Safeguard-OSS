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
import { buildLevelConfig } from '../src/config/securityLevels.js';

describe('buildLevelConfig', () => {
  it('derives monotonic thresholds across levels', () => {
    const low = buildLevelConfig(0);
    const mid = buildLevelConfig(5);
    const high = buildLevelConfig(10);
    expect(low.blockThreshold).toBeGreaterThan(mid.blockThreshold);
    expect(mid.blockThreshold).toBeGreaterThan(high.blockThreshold);
    expect(low.rateLimitPerMinute).toBeGreaterThan(high.rateLimitPerMinute);
    expect(low.maxViolationsBeforeLockout).toBeGreaterThanOrEqual(high.maxViolationsBeforeLockout);
  });

  it('gates feature flags by level', () => {
    expect(buildLevelConfig(1).enableObfuscationDecoding).toBe(false);
    expect(buildLevelConfig(2).enableObfuscationDecoding).toBe(true);
    expect(buildLevelConfig(3).enableSemanticSimilarity).toBe(false);
    expect(buildLevelConfig(4).enableSemanticSimilarity).toBe(true);
    expect(buildLevelConfig(4).enableStrictPII).toBe(false);
    expect(buildLevelConfig(5).enableStrictPII).toBe(true);
    expect(buildLevelConfig(3).enableToolStrictMode).toBe(true);
    expect(buildLevelConfig(2).enableMultilingualIntent).toBe(true);
    expect(buildLevelConfig(1).enableMultilingualIntent).toBe(false);
    expect(buildLevelConfig(3).enableStatisticalIntent).toBe(true);
    expect(buildLevelConfig(4).enableSessionTracking).toBe(true);
  });

  it('disables lockout duration at level 0', () => {
    expect(buildLevelConfig(0).lockoutDurationMs).toBe(0);
  });
});
