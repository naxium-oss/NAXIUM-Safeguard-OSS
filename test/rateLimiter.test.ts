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
import { RateLimiter } from '../src/protection/rateLimiter.js';

describe('RateLimiter', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('allows under the limit and decrements remaining', () => {
    const rl = new RateLimiter(3);
    expect(rl.check('a')).toEqual({ allowed: true, remaining: 2 });
    expect(rl.check('a')).toEqual({ allowed: true, remaining: 1 });
    expect(rl.check('a')).toEqual({ allowed: true, remaining: 0 });
    expect(rl.check('a')).toEqual({ allowed: false, remaining: 0 });
  });

  it('isolates keys', () => {
    const rl = new RateLimiter(1);
    expect(rl.check('a').allowed).toBe(true);
    expect(rl.check('b').allowed).toBe(true);
    expect(rl.check('a').allowed).toBe(false);
  });

  it('expires stamps after the sliding window', () => {
    const rl = new RateLimiter(1);
    expect(rl.check('a').allowed).toBe(true);
    expect(rl.check('a').allowed).toBe(false);
    vi.advanceTimersByTime(60_001);
    expect(rl.check('a').allowed).toBe(true);
  });

  it('reset clears a key', () => {
    const rl = new RateLimiter(1);
    rl.check('a');
    expect(rl.check('a').allowed).toBe(false);
    rl.reset('a');
    expect(rl.check('a').allowed).toBe(true);
  });
});
