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
import { loadDataFile } from '../utils/loadJson.js';
import type { DetectionSignal } from '../types.js';

interface LexEntry {
  lang: string;
  pattern: string;
  weight: number;
}

interface MultilingualBank {
  override: LexEntry[];
  persona: LexEntry[];
  harm: LexEntry[];
}

const bank = loadDataFile<MultilingualBank>('multilingualLexicon.json');

const compiled = {
  override: bank.override.map((e) => ({ ...e, re: new RegExp(e.pattern, 'i') })),
  persona: bank.persona.map((e) => ({ ...e, re: new RegExp(e.pattern, 'i') })),
  harm: bank.harm.map((e) => ({ ...e, re: new RegExp(e.pattern, 'i') })),
};

const MAX_TEXT = 16_384;

/**
 * Non-English jailbreak and harm cues.
 *
 * Attackers routinely switch languages to dodge English-only regex banks.
 * This layer is data-driven (see multilingualLexicon.json) and scores the
 * strongest family hit per request.
 */
export function detectMultilingualIntent(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 8 || rawText.length > MAX_TEXT) return [];

  const matched: string[] = [];
  let best = { score: 0, category: '', lang: '' };

  const scan = (
    entries: typeof compiled.override,
    category: string,
  ): void => {
    for (const entry of entries) {
      const hit = rawText.match(entry.re);
      if (!hit) continue;
      matched.push(`${entry.lang}:${hit[0].slice(0, 40)}`);
      if (entry.weight > best.score) {
        best = { score: entry.weight, category, lang: entry.lang };
      }
    }
  };

  scan(compiled.override, 'instruction_override');
  scan(compiled.persona, 'roleplay_bypass');
  scan(compiled.harm, 'multilingual_harm');

  if (best.score < 0.5) return [];

  return [
    {
      detector: 'multilingualIntent',
      category: best.category,
      score: Math.min(1, best.score),
      weight: 1,
      tier: 'primary',
      reliability: 0.88,
      matched: matched.slice(0, 6),
      details: `Multilingual jailbreak cue (${best.lang})`,
    },
  ];
}
