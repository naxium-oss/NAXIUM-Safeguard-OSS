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
import { parseCliArgs } from '../src/cli/parseArgs.js';

describe('parseCliArgs', () => {
  it('parses command, flags, and positionals', () => {
    const result = parseCliArgs(['check-input', 'hello', 'world', '--level', '8']);
    expect(result.cmd).toBe('check-input');
    expect(result.positional).toEqual(['hello', 'world']);
    expect(result.options.level).toBe('8');
  });

  it('throws when a flag is missing its value', () => {
    expect(() => parseCliArgs(['check-input', 'hi', '--level'])).toThrow(/Missing value for --level/);
  });

  it('allows empty argv for TUI default', () => {
    expect(parseCliArgs([]).cmd).toBeUndefined();
  });
});
