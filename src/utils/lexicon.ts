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
import { loadDataFile } from './loadJson.js';

/**
 * Shared lexical baseline.
 *
 * Several layers need to know what ordinary language looks like: TF-IDF needs
 * stopwords, the character n-gram layer needs to ignore risky-looking
 * substrings inside everyday words ("password", "shell", "reverse"), and the
 * token layer needs to know when a risky verb has a harmless object.
 */
interface LexicalBaseline {
  stopwords: string[];
  commonWords: string[];
  benignObjects: string[];
}

interface BenignExample {
  id: string;
  domain: string;
  text: string;
}

const baseline = loadDataFile<LexicalBaseline>('lexicalBaseline.json');

export const STOPWORDS: ReadonlySet<string> = new Set(baseline.stopwords);
export const BENIGN_OBJECTS: readonly string[] = baseline.benignObjects;

export const BENIGN_EXAMPLES: readonly BenignExample[] =
  loadDataFile<BenignExample[]>('benignCorpus.json');

/**
 * Everyday vocabulary: the curated common-word list plus every word that
 * appears in the committed benign corpus. Words here never contribute
 * character-gram risk on their own.
 */
export const COMMON_WORDS: ReadonlySet<string> = (() => {
  const words = new Set<string>([...baseline.stopwords, ...baseline.commonWords]);
  for (const example of BENIGN_EXAMPLES) {
    for (const token of tokenizeWords(example.text)) {
      if (token.length >= 3) words.add(token);
    }
  }
  return words;
})();

const SUFFIXES = ['s', 'es', 'ed', 'ing', 'er', 'ers', 'ly', 'd', 'ion', 'ions'];

export function tokenizeWords(text: string): string[] {
  return text.toLowerCase().match(/[a-z][a-z'-]*[a-z]|[a-z]/g) ?? [];
}

/** Tokens with stopwords removed — the content-bearing words. */
export function contentTokens(text: string): string[] {
  return tokenizeWords(text).filter((t) => t.length > 1 && !STOPWORDS.has(t));
}

/** True for everyday words, including simple inflections of them. */
export function isCommonWord(word: string): boolean {
  const w = word.toLowerCase();
  if (COMMON_WORDS.has(w)) return true;
  for (const suffix of SUFFIXES) {
    if (w.length > suffix.length + 2 && w.endsWith(suffix)) {
      const stem = w.slice(0, -suffix.length);
      if (COMMON_WORDS.has(stem)) return true;
      if (COMMON_WORDS.has(`${stem}e`)) return true;
      if (stem.length > 2 && stem[stem.length - 1] === stem[stem.length - 2]) {
        if (COMMON_WORDS.has(stem.slice(0, -1))) return true;
      }
    }
  }
  return false;
}
