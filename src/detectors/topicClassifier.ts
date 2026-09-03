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

/** Short single words need word boundaries so they cannot match inside words. */
const BOUNDED_MAX_LENGTH = 9;

interface CompiledTerm extends Term {
  words: number;
  regex?: RegExp;
}

interface CompiledLexicon extends Omit<Lexicon, 'terms'> {
  terms: CompiledTerm[];
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const COMPILED: CompiledLexicon[] = LEXICONS.map((lex) => ({
  ...lex,
  terms: lex.terms.map((t) => {
    const words = t.term.trim().split(/\s+/).length;
    const needsBoundary = words === 1 && t.term.length <= BOUNDED_MAX_LENGTH;
    return {
      ...t,
      words,
      regex: needsBoundary ? new RegExp(`\\b${escapeRegex(t.term)}\\b`, 'i') : undefined,
    };
  }),
}));

/** Harmless compounds that contain weapons tokens ("bath bomb", "f-bomb"). */
const BENIGN_COMPOUND =
  /\b(?:bath|photo|seed|paint|water|cherry)\s+bombs?\b|\bf-?bombs?\b/gi;

/** Blank out benign compounds so combo boosters cannot fire on craft recipes. */
function maskBenignCompounds(text: string): string {
  return text.replace(BENIGN_COMPOUND, ' ');
}

const MAX_MATCHED_REPORTED = 10;
/** A multi-word phrase is specific enough to stand alone as evidence. */
const PRIMARY_SINGLE_WORD_WEIGHT = 0.6;

/**
 * Topic lexicon layer.
 *
 * Beyond raw matching it distinguishes *specific* evidence from *generic*
 * evidence: a multi-word phrase ("build a pipe bomb") is a request, whereas a
 * single common-weight word ("ransomware") is only a topic mention and is
 * emitted as corroborating so it cannot block on its own. Hard-block
 * categories bypass all of this by design.
 */
export function classifyTopics(rawText: string): DetectionSignal[] {
  const text = maskBenignCompounds(rawText.toLowerCase());
  const signals: DetectionSignal[] = [];

  for (const lex of COMPILED) {
    let score = 0;
    const matched: string[] = [];
    let specific = false;
    let maxWeight = 0;

    for (const t of lex.terms) {
      const hit = t.regex ? t.regex.test(text) : text.includes(t.term);
      if (!hit) continue;
      score += t.weight;
      maxWeight = Math.max(maxWeight, t.weight);
      if (t.words >= 2) specific = true;
      if (matched.length < MAX_MATCHED_REPORTED) matched.push(t.term);
    }

    // Combos can establish a hit on their own (e.g. "make"+"bomb" with no
    // longer lexicon phrase), not only as a bonus on an existing term match.
    if (lex.comboBoosters) {
      for (const combo of lex.comboBoosters) {
        if (text.includes(combo.terms[0]) && text.includes(combo.terms[1])) {
          score += combo.bonus;
          specific = true;
          if (matched.length < MAX_MATCHED_REPORTED) {
            matched.push(`${combo.terms[0]}+${combo.terms[1]}`);
          }
        }
      }
    }

    if (matched.length === 0) continue;

    const primary = Boolean(lex.hardBlock) || specific || maxWeight >= PRIMARY_SINGLE_WORD_WEIGHT;

    signals.push({
      detector: 'topicClassifier',
      category: lex.category,
      score: lex.hardBlock ? 1 : Math.min(1, score),
      weight: 1,
      tier: primary ? 'primary' : 'corroborating',
      reliability: 0.95,
      matched,
      details: lex.hardBlock ? 'hard-block category' : `${matched.length} lexicon term(s)`,
    });
  }

  return signals;
}
