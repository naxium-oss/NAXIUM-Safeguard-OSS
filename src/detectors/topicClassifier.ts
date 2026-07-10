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

interface Term {
  term: string;
  weight: number;
}
interface ComboBooster {
  terms: [string, string];
  bonus: number;
}
interface Lexicon {
  category: string;
  hardBlock?: boolean;
  terms: Term[];
  comboBoosters?: ComboBooster[];
}

const LEXICONS = loadDataFile<Lexicon[]>('topicLexicons.json');

export function classifyTopics(rawText: string): DetectionSignal[] {
  const text = rawText.toLowerCase();
  const signals: DetectionSignal[] = [];

  for (const lex of LEXICONS) {
    let score = 0;
    const matched: string[] = [];

    for (const t of lex.terms) {
      if (text.includes(t.term)) {
        score += t.weight;
        matched.push(t.term);
      }
    }

    if (lex.comboBoosters) {
      for (const combo of lex.comboBoosters) {
        if (text.includes(combo.terms[0]) && text.includes(combo.terms[1])) {
          score += combo.bonus;
        }
      }
    }

    if (matched.length === 0) continue;

    signals.push({
      detector: 'topicClassifier',
      category: lex.category,
      score: lex.hardBlock ? 1 : Math.min(1, score),
      weight: 1,
      matched,
      details: lex.hardBlock ? 'hard-block category' : undefined,
    });
  }

  return signals;
}
