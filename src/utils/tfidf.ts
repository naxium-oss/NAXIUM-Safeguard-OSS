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
import { contentTokens } from './lexicon.js';

/**
 * Small local TF-IDF index used for nearest-neighbour comparison against
 * committed corpora. Stopwords are dropped, term frequency is sublinear and
 * word bigrams are indexed alongside unigrams so shared filler phrasing
 * ("give me", "can you") cannot drive similarity on its own.
 */
export interface TfidfModel {
  vocab: Map<string, number>;
  idf: Float64Array;
  docVectors: Float64Array[];
}

export interface MatchResult {
  index: number;
  sim: number;
}

function featurize(text: string): string[] {
  const tokens = contentTokens(text);
  const features = [...tokens];
  for (let i = 0; i + 1 < tokens.length; i++) {
    features.push(`${tokens[i]}_${tokens[i + 1]}`);
  }
  return features;
}

export function buildTfidfModel(docs: string[]): TfidfModel {
  const vocab = new Map<string, number>();
  const docFeatures = docs.map(featurize);

  for (const features of docFeatures) {
    for (const feature of new Set(features)) {
      if (!vocab.has(feature)) vocab.set(feature, vocab.size);
    }
  }

  const df = new Float64Array(vocab.size);
  for (const features of docFeatures) {
    for (const feature of new Set(features)) df[vocab.get(feature)!]++;
  }

  const n = docs.length;
  const idf = new Float64Array(vocab.size);
  for (let i = 0; i < idf.length; i++) idf[i] = Math.log((n + 1) / (df[i] + 1)) + 1;

  const docVectors = docFeatures.map((features) => vectorize(features, vocab, idf));
  return { vocab, idf, docVectors };
}

function vectorize(features: string[], vocab: Map<string, number>, idf: Float64Array): Float64Array {
  const vec = new Float64Array(vocab.size);
  const counts = new Map<string, number>();
  for (const feature of features) counts.set(feature, (counts.get(feature) ?? 0) + 1);

  for (const [feature, count] of counts) {
    const idx = vocab.get(feature);
    // Sublinear term frequency: repetition should not dominate similarity.
    if (idx !== undefined) vec[idx] = (1 + Math.log(count)) * idf[idx];
  }
  return normalize(vec);
}

function normalize(vec: Float64Array): Float64Array {
  let norm = 0;
  for (const v of vec) norm += v * v;
  norm = Math.sqrt(norm) || 1;
  const out = new Float64Array(vec.length);
  for (let i = 0; i < vec.length; i++) out[i] = vec[i] / norm;
  return out;
}

export function vectorizeQuery(text: string, model: TfidfModel): Float64Array {
  return vectorize(featurize(text), model.vocab, model.idf);
}

export function cosineSim(a: Float64Array, b: Float64Array): number {
  let dot = 0;
  for (let i = 0; i < a.length; i++) dot += a[i] * b[i];
  return dot;
}

/** Nearest document among `candidates` (defaults to every document). */
export function bestMatch(
  query: Float64Array,
  model: TfidfModel,
  candidates?: readonly number[],
): MatchResult {
  const indices = candidates ?? model.docVectors.map((_, i) => i);
  let best: MatchResult = { index: -1, sim: 0 };
  for (const index of indices) {
    const vec = model.docVectors[index];
    if (!vec) continue;
    const sim = cosineSim(query, vec);
    if (sim > best.sim) best = { index, sim };
  }
  return best;
}

/** Number of content features the query shares with a specific document. */
export function sharedFeatureCount(query: Float64Array, model: TfidfModel, index: number): number {
  const doc = model.docVectors[index];
  if (!doc) return 0;
  let shared = 0;
  for (let i = 0; i < query.length; i++) {
    if (query[i] > 0 && doc[i] > 0) shared += 1;
  }
  return shared;
}
