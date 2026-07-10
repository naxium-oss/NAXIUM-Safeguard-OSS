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
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { BruteForceGuard } from '../src/protection/bruteForceGuard.js';

describe('BruteForceGuard', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('locks after max violations', () => {
    const g = new BruteForceGuard(2, 60_000);
    expect(g.recordViolation('a').lockedOut).toBe(false);
    expect(g.recordViolation('a').lockedOut).toBe(true);
    expect(g.isLockedOut('a')).toBe(true);
  });

  it('does not increment while already locked', () => {
    const g = new BruteForceGuard(1, 60_000);
    g.recordViolation('a');
    const second = g.recordViolation('a');
    expect(second.lockedOut).toBe(true);
    expect(second.violations).toBe(1);
  });

  it('expires lockout', () => {
    const g = new BruteForceGuard(1, 5_000);
    g.recordViolation('a');
    expect(g.isLockedOut('a')).toBe(true);
    vi.advanceTimersByTime(5_001);
    expect(g.isLockedOut('a')).toBe(false);
  });

  it('never locks when duration is 0', () => {
    const g = new BruteForceGuard(1, 0);
    g.recordViolation('a');
    expect(g.isLockedOut('a')).toBe(false);
  });

  it('reset clears lockout', () => {
    const g = new BruteForceGuard(1, 60_000);
    g.recordViolation('a');
    g.reset('a');
    expect(g.isLockedOut('a')).toBe(false);
  });
});
