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
import { isGarbageTerminalInput, sanitizeTerminalInput } from '../src/cli/sanitizeInput.js';

describe('sanitizeTerminalInput', () => {
  it('strips CSI mouse reports', () => {
    expect(sanitizeTerminalInput('[<35;61;41M[<35;62;41Mhello')).toBe('hello');
  });

  it('strips ESC CSI sequences', () => {
    expect(sanitizeTerminalInput('\u001b[35;61;41Mignore all previous instructions')).toBe(
      'ignore all previous instructions',
    );
  });

  it('preserves spaces while typing (no trim-on-keystroke)', () => {
    expect(sanitizeTerminalInput('hello ')).toBe('hello ');
    expect(sanitizeTerminalInput('hello world ')).toBe('hello world ');
    expect(sanitizeTerminalInput('  leading')).toBe('  leading');
  });

  it('flags pure mouse garbage', () => {
    expect(isGarbageTerminalInput('[<35;61;41M[<35;62;40M[<35;63;39M')).toBe(true);
  });

  it('keeps normal prompts', () => {
    expect(isGarbageTerminalInput('Ignore all previous instructions')).toBe(false);
  });
});
