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
import { isCommonWord, tokenizeWords } from '../utils/lexicon.js';
import type { DetectionSignal } from '../types.js';

/**
 * Character n-gram layer — a spelling-level view that survives mutations the
 * word lexicons miss ("r4nsomw@re", "exfiltraiton").
 *
 * Scoring is per word and requires *chained* grams: several consecutive
 * in-bank 4-grams covering a long enough stem. Matching a single gram inside
 * an ordinary word ("pass" in password, "shel" in shell) proves nothing, and
 * words that exist in everyday vocabulary are skipped outright. Output is
 * always corroborating — this layer supports other evidence, never blocks on
 * its own.
 */
interface NgramBank {
  grams: { gram: string; weight: number }[];
}

const bank = loadDataFile<NgramBank>('ngramRiskBank.json');
const GRAM_WEIGHTS = new Map<string, number>();
for (const entry of bank.grams) {
  if (entry.gram.length === 4) GRAM_WEIGHTS.set(entry.gram, entry.weight);
}

const MIN_TEXT_CHARS = 10;
const MAX_TEXT_CHARS = 8_192;
const MIN_WORD_LENGTH = 5;
/** Consecutive in-bank 4-grams needed before a stem counts as risky. */
const MIN_CHAIN = 3;
/** Characters a chain must cover (MIN_CHAIN consecutive 4-grams => 6). */
const MIN_COVERAGE = 6;
const MAX_SCORE = 0.35;

interface WordHit {
  word: string;
  coverage: number;
  weight: number;
}

/** Longest run of consecutive in-bank 4-grams inside a single word. */
function scoreWord(word: string): WordHit | null {
  if (word.length < MIN_WORD_LENGTH) return null;

  let bestRun = 0;
  let bestWeight = 0;
  let run = 0;
  let runWeight = 0;

  for (let i = 0; i + 4 <= word.length; i++) {
    const weight = GRAM_WEIGHTS.get(word.slice(i, i + 4));
    if (weight === undefined) {
      run = 0;
      runWeight = 0;
      continue;
    }
    run += 1;
    runWeight += weight;
    if (run > bestRun) {
      bestRun = run;
      bestWeight = runWeight;
    }
  }

  if (bestRun < MIN_CHAIN) return null;
  const coverage = bestRun + 3;
  if (coverage < MIN_COVERAGE) return null;
  return { word, coverage, weight: bestWeight };
}

export function detectNgramRisk(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < MIN_TEXT_CHARS || rawText.length > MAX_TEXT_CHARS) return [];

  const words = new Set(tokenizeWords(rawText.replace(/[^a-zA-Z0-9\s]+/g, ' ')));
  const hits: WordHit[] = [];

  for (const word of words) {
    if (isCommonWord(word)) continue;
    const hit = scoreWord(word);
    if (hit) hits.push(hit);
    if (hits.length >= 8) break;
  }

  if (hits.length === 0) return [];

  // One short stem is weak; long coverage or several distinct words is not.
  const strong = hits.some((h) => h.coverage >= 8);
  if (hits.length < 2 && !strong) return [];

  const raw = hits.reduce((sum, h) => sum + h.weight, 0) + (strong ? 0.1 : 0);
  const score = Math.min(MAX_SCORE, raw);

  return [
    {
      detector: 'ngramRisk',
      category: 'ngram_risk',
      score,
      weight: 1,
      tier: 'corroborating',
      reliability: 0.7,
      matched: hits.map((h) => h.word).slice(0, 8),
      details: `Risky character-gram chains in ${hits.length} uncommon word(s)`,
    },
  ];
}
