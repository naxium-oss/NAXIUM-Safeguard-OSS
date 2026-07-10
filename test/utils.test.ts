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
import { timingSafeEqualString } from '../src/utils/timingSafeEqual.js';
import { deepMerge } from '../src/utils/deepMerge.js';
import { parseSecurityLevel } from '../src/utils/parseSecurityLevel.js';
import { BoundedMap } from '../src/utils/boundedMap.js';

describe('timingSafeEqualString', () => {
  it('matches equal strings', () => {
    expect(timingSafeEqualString('abc', 'abc')).toBe(true);
  });
  it('rejects unequal strings', () => {
    expect(timingSafeEqualString('abc', 'abd')).toBe(false);
    expect(timingSafeEqualString('abc', 'ab')).toBe(false);
  });
});

describe('deepMerge', () => {
  it('merges nested objects without dropping defaults', () => {
    const merged = deepMerge(
      { logging: { enabled: false, logSafeRequests: false }, name: 'a' },
      { logging: { enabled: true } },
    );
    expect(merged.logging.enabled).toBe(true);
    expect(merged.logging.logSafeRequests).toBe(false);
    expect(merged.name).toBe('a');
  });

  it('ignores prototype-pollution keys', () => {
    const merged = deepMerge(
      { safe: true } as Record<string, unknown>,
      { __proto__: { polluted: true }, constructor: { polluted: true } } as Record<string, unknown>,
    );
    expect(merged.safe).toBe(true);
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined();
  });
});

describe('parseSecurityLevel', () => {
  it('parses valid levels and falls back otherwise', () => {
    expect(parseSecurityLevel(7)).toBe(7);
    expect(parseSecurityLevel('3')).toBe(3);
    expect(parseSecurityLevel('nope', 6)).toBe(6);
    expect(parseSecurityLevel(11, 6)).toBe(6);
  });
});

describe('BoundedMap', () => {
  it('evicts oldest when over capacity', () => {
    const map = new BoundedMap<number>(2);
    map.set('a', 1);
    map.set('b', 2);
    map.set('c', 3);
    expect(map.get('a')).toBeUndefined();
    expect(map.get('b')).toBe(2);
    expect(map.get('c')).toBe(3);
  });
});
