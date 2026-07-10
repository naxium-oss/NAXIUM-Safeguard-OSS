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
import { scanForSecrets } from '../src/detectors/secretsScanner.js';
import { FIXTURES } from './helpers/secretFixtures.js';

describe('secretsScanner', () => {
  it('detects openai-style keys', () => {
    const signals = scanForSecrets(`key=${FIXTURES.openai()}`);
    expect(signals.some((s) => s.category === 'secret_leak')).toBe(true);
    expect(signals[0]?.matched[0]).toMatch(/\.\.\./);
  });

  it('detects modern project and github_pat keys', () => {
    expect(scanForSecrets(FIXTURES.openaiProject()).some((s) => s.category === 'secret_leak')).toBe(true);
    expect(scanForSecrets(FIXTURES.githubPatFine()).some((s) => s.category === 'secret_leak')).toBe(true);
    expect(scanForSecrets(FIXTURES.huggingFace()).some((s) => s.category === 'secret_leak')).toBe(true);
  });

  it('detects Stripe and npm tokens', () => {
    expect(scanForSecrets(FIXTURES.stripeLive()).some((s) => s.category === 'secret_leak')).toBe(true);
    expect(scanForSecrets(FIXTURES.npm()).some((s) => s.category === 'secret_leak')).toBe(true);
  });

  it('detects high-entropy tokens', () => {
    const tok = 'aB3dE5fG7hI9jK1lM2nO4pQ6rS8tU0vW';
    const signals = scanForSecrets(`token ${tok}`);
    expect(signals.some((s) => s.category === 'secret_leak_entropy')).toBe(true);
  });

  it('ignores short low-entropy words', () => {
    const signals = scanForSecrets('hello world this is fine');
    expect(signals).toHaveLength(0);
  });
});
