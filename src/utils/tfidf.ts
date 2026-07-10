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
export interface TfidfModel {
  vocab: Map<string, number>;
  idf: Float64Array;
  docVectors: Float64Array[];
}

function tokenize(text: string): string[] {
  return text.toLowerCase().match(/[a-z0-9']+/g) ?? [];
}

export function buildTfidfModel(docs: string[]): TfidfModel {
  const vocab = new Map<string, number>();
  const docTokens = docs.map(tokenize);

  for (const tokens of docTokens) {
    for (const tok of new Set(tokens)) {
      if (!vocab.has(tok)) vocab.set(tok, vocab.size);
    }
  }

  const df = new Float64Array(vocab.size);
  for (const tokens of docTokens) {
    for (const tok of new Set(tokens)) df[vocab.get(tok)!]++;
  }

  const N = docs.length;
  const idf = new Float64Array(vocab.size);
  for (let i = 0; i < idf.length; i++) idf[i] = Math.log((N + 1) / (df[i] + 1)) + 1;

  const docVectors = docTokens.map((tokens) => vectorize(tokens, vocab, idf));
  return { vocab, idf, docVectors };
}

function vectorize(tokens: string[], vocab: Map<string, number>, idf: Float64Array): Float64Array {
  const vec = new Float64Array(vocab.size);
  const counts = new Map<string, number>();
  for (const t of tokens) counts.set(t, (counts.get(t) ?? 0) + 1);

  for (const [tok, count] of counts) {
    const idx = vocab.get(tok);
    if (idx !== undefined && tokens.length > 0) vec[idx] = (count / tokens.length) * idf[idx];
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
  return vectorize(tokenize(text), model.vocab, model.idf);
}

export function cosineSim(a: Float64Array, b: Float64Array): number {
  let dot = 0;
  for (let i = 0; i < a.length; i++) dot += a[i] * b[i];
  return dot;
}
