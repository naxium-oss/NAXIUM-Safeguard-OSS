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
import { buildTfidfModel, vectorizeQuery, cosineSim } from '../utils/tfidf.js';
import type { DetectionSignal } from '../types.js';

interface AttackExample {
  id: string;
  category: string;
  text: string;
}

const corpus = loadDataFile<AttackExample[]>('knownAttackCorpus.json');
const model = buildTfidfModel(corpus.map((c) => c.text));

/**
 * Catches paraphrases of known attack templates that exact-match regex
 * patterns would miss. Purely local TF-IDF cosine similarity — no network
 * calls, no external models.
 */
export function semanticSimilarityCheck(text: string, threshold = 0.42): DetectionSignal[] {
  // Skip pathological inputs — TF-IDF over megabyte strings is a CPU DoS vector
  if (!text || text.length > 16_384) return [];

  // Short benign prompts ("secure my site") false-positive easily against a
  // large attack corpus — require a stricter match for brief inputs.
  const tokenCount = text.trim().split(/\s+/).filter(Boolean).length;
  const effectiveThreshold = tokenCount <= 5 ? Math.max(threshold, 0.55) : threshold;

  const qVec = vectorizeQuery(text, model);
  let best = { sim: 0, idx: -1 };

  model.docVectors.forEach((vec, idx) => {
    const sim = cosineSim(qVec, vec);
    if (sim > best.sim) best = { sim, idx };
  });

  if (best.idx === -1 || best.sim < effectiveThreshold) return [];

  const example = corpus[best.idx];
  return [
    {
      detector: 'semanticSimilarity',
      category: example.category,
      score: Math.min(1, best.sim),
      weight: 1,
      matched: [example.id],
      details: `Similar to known attack pattern (cosine=${best.sim.toFixed(2)})`,
    },
  ];
}
