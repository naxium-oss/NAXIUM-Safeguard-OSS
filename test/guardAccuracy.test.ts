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
import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';
import { NaxiumSafeguard } from '../src/index.js';
import { DEFAULT_CLI_LEVEL } from '../src/cli/defaults.js';

const benign = JSON.parse(
  readFileSync(new URL('./fixtures/benignPrompts.json', import.meta.url), 'utf8'),
) as string[];

const evasions = JSON.parse(
  readFileSync(new URL('./fixtures/evasionAttacks.json', import.meta.url), 'utf8'),
) as { id: string; family: string; prompt: string }[];

describe('guard accuracy floors @ default CLI level', () => {
  const guard = new NaxiumSafeguard({
    securityLevel: DEFAULT_CLI_LEVEL,
    logging: { enabled: false, logSafeRequests: false },
  });

  it('allows every curated benign prompt (zero false blocks)', () => {
    const blocked = benign.filter((prompt) => {
      const result = guard.guardInput(prompt, {
        sessionId: `benign-${prompt.length}`,
        protectionKey: `benign-${prompt.slice(0, 16)}`,
      });
      return !result.safe && result.action === 'block';
    });
    expect(blocked, `false blocks: ${blocked.join(' | ')}`).toEqual([]);
  });

  it('catches at least 95% of curated evasion attacks', () => {
    const missed = evasions.filter((attack) => {
      const result = guard.guardInput(attack.prompt, {
        sessionId: attack.id,
        protectionKey: attack.id,
      });
      return result.safe;
    });
    const catchRate = (evasions.length - missed.length) / evasions.length;
    expect(
      catchRate,
      `missed (${missed.length}): ${missed.map((m) => `${m.id} ${m.family}`).join('; ')}`,
    ).toBeGreaterThanOrEqual(0.95);
  });
});
