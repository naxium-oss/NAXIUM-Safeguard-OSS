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

/**
 * Character n-gram risk scoring — a different method from regex/lexicon
 * exact match. Scores overlap of 3–4 character grams against a risk lexicon
 * so lightly mutated spellings still accumulate signal.
 */
interface NgramBank {
  grams: { gram: string; weight: number }[];
}

const bank = loadDataFile<NgramBank>('ngramRiskBank.json');

function extractGrams(text: string, n: number): Set<string> {
  const cleaned = text.toLowerCase().replace(/[^a-z0-9]/g, '');
  const out = new Set<string>();
  if (cleaned.length < n) return out;
  for (let i = 0; i <= cleaned.length - n; i++) {
    out.add(cleaned.slice(i, i + n));
  }
  return out;
}

export function detectNgramRisk(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 10 || rawText.length > 8_192) return [];

  // Skip very short token counts — "hello" shares trigrams with "shell"
  const tokenCount = rawText.trim().split(/\s+/).filter(Boolean).length;
  if (tokenCount < 2 && rawText.length < 12) return [];

  const grams3 = extractGrams(rawText, 3);
  const grams4 = extractGrams(rawText, 4);
  if (grams4.size === 0 && grams3.size < 6) return [];

  let score4 = 0;
  let score3 = 0;
  const matched4: string[] = [];
  const matched3: string[] = [];

  for (const g of bank.grams) {
    if (g.gram.length === 4 && grams4.has(g.gram)) {
      score4 += g.weight;
      if (matched4.length < 10) matched4.push(g.gram);
    } else if (g.gram.length === 3 && grams3.has(g.gram)) {
      score3 += g.weight * 0.35; // 3-grams are corroboration only
      if (matched3.length < 8) matched3.push(g.gram);
    }
  }

  // Require real 4-gram overlap; 3-grams alone must not flag ("hel"/"ell"/"hell")
  if (matched4.length < 2) return [];
  const score = score4 + Math.min(0.15, score3);
  if (score < 0.4) return [];

  return [
    {
      detector: 'ngramRisk',
      category: 'ngram_risk',
      score: Math.min(1, score),
      weight: 0.85,
      matched: [...matched4, ...matched3].slice(0, 12),
      details: `N-gram risk overlap (${matched4.length} 4-grams)`,
    },
  ];
}
