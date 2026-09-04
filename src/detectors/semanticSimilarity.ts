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
import { buildTfidfModel, vectorizeQuery, bestMatch, sharedFeatureCount } from '../utils/tfidf.js';
import { BENIGN_EXAMPLES } from '../utils/lexicon.js';
import { loadDataFile } from '../utils/loadJson.js';
import type { DetectionSignal } from '../types.js';

interface AttackExample {
  id: string;
  category: string;
  text: string;
}

const corpus = loadDataFile<AttackExample[]>('knownAttackCorpus.json');

/**
 * One index over both corpora so attack and benign similarities share an IDF
 * space and can be compared directly.
 */
const model = buildTfidfModel([
  ...corpus.map((c) => c.text),
  ...BENIGN_EXAMPLES.map((b) => b.text),
]);
const ATTACK_INDICES = corpus.map((_, i) => i);
const BENIGN_INDICES = BENIGN_EXAMPLES.map((_, i) => corpus.length + i);

const MAX_TEXT_CHARS = 16_384;
/** Below this, a match is noise no matter how the benign side scores. */
const ABSOLUTE_FLOOR = 0.3;
/** Attack similarity must beat the nearest benign example by this much. */
const MARGIN_FLOOR = 0.12;
/** Short inputs share too little signal to trust a nearest-neighbour verdict. */
const SHORT_INPUT_TOKENS = 6;
const SHORT_INPUT_FLOOR = 0.55;
/** A single overlapping feature is a coincidence, not a paraphrase. */
const MIN_SHARED_FEATURES = 3;

/**
 * Contrastive nearest-neighbour check against the local corpora.
 *
 * Similarity to an attack template only counts when the text is *more* like
 * that attack than like anything in the benign corpus. This is what stops
 * ordinary requests that happen to share filler phrasing with an attack
 * template ("give me a recipe for…") from scoring as paraphrased jailbreaks.
 */
export function semanticSimilarityCheck(text: string, threshold = 0.42): DetectionSignal[] {
  // Skip pathological inputs — TF-IDF over megabyte strings is a CPU DoS vector
  if (!text || text.length > MAX_TEXT_CHARS) return [];

  const tokenCount = text.trim().split(/\s+/).filter(Boolean).length;
  const effectiveThreshold = Math.max(
    ABSOLUTE_FLOOR,
    tokenCount <= SHORT_INPUT_TOKENS ? Math.max(threshold, SHORT_INPUT_FLOOR) : threshold,
  );

  const query = vectorizeQuery(text, model);
  const attack = bestMatch(query, model, ATTACK_INDICES);
  if (attack.index === -1 || attack.sim < effectiveThreshold) return [];
  if (sharedFeatureCount(query, model, attack.index) < MIN_SHARED_FEATURES) return [];

  const benign = bestMatch(query, model, BENIGN_INDICES);
  const margin = attack.sim - benign.sim;
  if (margin < MARGIN_FLOOR) return [];

  const example = corpus[attack.index];
  // Confidence follows the margin, not the raw similarity: a text that looks
  // equally like both corpora is not evidence of anything.
  const score = Math.min(1, attack.sim * (0.55 + Math.min(0.45, margin)));

  return [
    {
      detector: 'semanticSimilarity',
      category: example.category,
      score,
      weight: 1,
      tier: score >= 0.55 ? 'primary' : 'corroborating',
      reliability: 0.9,
      matched: [example.id],
      details: `Similar to known attack pattern (cosine=${attack.sim.toFixed(2)}, margin=${margin.toFixed(2)})`,
    },
  ];
}
