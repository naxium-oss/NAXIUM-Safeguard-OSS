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

/**
 * One test per Jailbreak Attack paper in
 * https://github.com/yueliu1999/Awesome-Jailbreak-on-LLMs
 *
 * Anti-benchmax rules:
 * - Prompts are technique-family templates (see scripts/generateAwesomeJailbreakFixtures.mjs).
 * - Paper titles are metadata only — never embedded in prompts for detectors to memorize.
 * - Do not add title-specific regexes to pass these tests.
 * - Failures mean the heuristic layer missed a real attack family — fix generally.
 *
 * Regenerate fixtures:
 *   npm run fixtures:awesome-jailbreak
 *   # → node scripts/regenerateAwesomeJailbreakFixtures.mjs
 */
const attacks = JSON.parse(
  readFileSync(new URL('./fixtures/awesomeJailbreakAttacks.json', import.meta.url), 'utf8'),
) as {
  id: string;
  category: string;
  title: string;
  family: string;
  prompt: string;
}[];

describe('Awesome-Jailbreak-on-LLMs — every attack paper must be flagged', () => {
  const guard = new NaxiumSafeguard({
    securityLevel: DEFAULT_CLI_LEVEL,
    logging: { enabled: false, logSafeRequests: false },
  });

  it('fixture covers the parsed attack bibliography', () => {
    expect(attacks.length).toBeGreaterThanOrEqual(200);
    const families = new Set(attacks.map((a) => a.family));
    expect(families.size).toBeGreaterThanOrEqual(8);
    // Technique variants, not one memorized string for the whole bib
    const uniquePrompts = new Set(attacks.map((a) => a.prompt));
    expect(uniquePrompts.size).toBeGreaterThanOrEqual(30);
  });

  it('prompts do not embed paper titles (anti-benchmax)', () => {
    for (const a of attacks) {
      // Long title tokens should not appear verbatim in the prompt (case-insensitive).
      // Skip common technique words that legitimately appear in both titles and attack language.
      const commonTechnique = new Set([
        'jailbreaking',
        'jailbreak',
        'adversarial',
        'instructions',
        'multimodal',
        'transferable',
        'unrestricted',
        'reasoning',
      ]);
      const distinctive = a.title
        .split(/[^A-Za-z0-9]+/)
        .filter((w) => w.length >= 12 && !commonTechnique.has(w.toLowerCase()));
      for (const w of distinctive) {
        expect(a.prompt.toLowerCase().includes(w.toLowerCase()), `${a.id} embeds title token ${w}`).toBe(
          false,
        );
      }
    }
  });

  it.each(attacks)('$id [$family] $category — $title', (attack) => {
    const result = guard.guardInput(attack.prompt, {
      sessionId: `aj-${attack.id}`,
      // Isolate rate limits per case
      protectionKey: `aj-${attack.id}`,
    });
    expect(
      result.safe,
      `${attack.id} "${attack.title}" family=${attack.family} score=${result.riskScore} action=${result.action}`,
    ).toBe(false);
    expect(result.signals.length).toBeGreaterThan(0);
  });
});
