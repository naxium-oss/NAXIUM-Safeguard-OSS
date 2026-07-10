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
import { detectPII } from '../src/detectors/piiDetector.js';

describe('piiDetector', () => {
  it('detects a valid credit card number via Luhn check', () => {
    const signals = detectPII('My card is 4111 1111 1111 1111', false);
    expect(signals.some((s) => s.category === 'pii_credit_card')).toBe(true);
  });

  it('ignores invalid card-like numbers', () => {
    const signals = detectPII('Order number 1234 5678 9012 3456', false);
    expect(signals.some((s) => s.category === 'pii_credit_card')).toBe(false);
  });
});
