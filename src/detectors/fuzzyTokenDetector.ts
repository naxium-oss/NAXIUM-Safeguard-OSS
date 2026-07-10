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

interface TokenEntry {
  token: string;
  weight: number;
}

const TOKENS = loadDataFile<TokenEntry[]>('highSignalTokens.json').filter(
  (t) => t.token.length >= 4 && t.weight >= 0.28,
);

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 2) return 99;
  const m = a.length;
  const n = b.length;
  const prev = new Array<number>(n + 1);
  const cur = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    cur[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    for (let j = 0; j <= n; j++) prev[j] = cur[j];
  }
  return prev[n];
}

/**
 * Fuzzy token layer — catches typos / light mutations of high-signal words
 * (e.g. "hackingg", "ransomwar", "phising") via bounded Levenshtein distance.
 * Exact matches are left to highSignalTokenDetector.
 */
export function detectFuzzyTokens(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 4 || rawText.length > 8_192) return [];

  const words = rawText.toLowerCase().match(/[a-z0-9][a-z0-9_-]{3,24}/g) ?? [];
  if (words.length === 0) return [];

  const matched: string[] = [];
  let score = 0;

  for (const w of words) {
    for (const t of TOKENS) {
      if (w === t.token) continue; // exact handled elsewhere
      if (Math.abs(w.length - t.token.length) > 2) continue;
      const dist = levenshtein(w, t.token);
      const maxDist = t.token.length >= 8 ? 2 : 1;
      if (dist > 0 && dist <= maxDist) {
        matched.push(`${w}~${t.token}`);
        score += t.weight * (dist === 1 ? 0.85 : 0.65);
        break;
      }
    }
    if (matched.length >= 6) break;
  }

  if (matched.length === 0) return [];

  return [
    {
      detector: 'fuzzyToken',
      category: 'fuzzy_attack_vocab',
      score: Math.min(1, score),
      weight: 1,
      matched: matched.slice(0, 8),
      details: 'Fuzzy match to high-signal attack vocabulary',
    },
  ];
}
