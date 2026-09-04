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

/** FNV-1a 32-bit hash for feature indexing. */
export function hashFeature(feature: string, seed = 0x811c9dc5): number {
  let h = seed >>> 0;
  for (let i = 0; i < feature.length; i++) {
    h ^= feature.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

export function featureIndex(feature: string, featureCount: number): number {
  return hashFeature(feature) % featureCount;
}

/** Word unigrams + character 3-grams for a compact local feature space. */
export function extractFeatures(text: string): string[] {
  const features: string[] = [];
  const tokens = contentTokens(text);
  for (const token of tokens) {
    features.push(`w:${token}`);
    if (token.length >= 4) {
      for (let i = 0; i <= token.length - 3; i++) {
        features.push(`c:${token.slice(i, i + 3)}`);
      }
    }
  }
  for (let i = 0; i + 1 < tokens.length; i++) {
    features.push(`b:${tokens[i]}_${tokens[i + 1]}`);
  }
  return features;
}

export interface SparseVector {
  indices: number[];
  values: number[];
}

/** L2-normalized hashed bag-of-features. */
export function vectorizeFeatures(text: string, featureCount: number): SparseVector {
  const counts = new Map<number, number>();
  for (const feature of extractFeatures(text)) {
    const idx = featureIndex(feature, featureCount);
    counts.set(idx, (counts.get(idx) ?? 0) + 1);
  }
  const indices: number[] = [];
  const values: number[] = [];
  let norm = 0;
  for (const [idx, count] of counts) {
    const value = 1 + Math.log(count);
    norm += value * value;
    indices.push(idx);
    values.push(value);
  }
  norm = Math.sqrt(norm) || 1;
  for (let i = 0; i < values.length; i++) values[i] /= norm;
  return { indices, values };
}

export function dotProduct(a: SparseVector, weights: Float64Array, bias: number): number {
  let sum = bias;
  for (let i = 0; i < a.indices.length; i++) {
    sum += a.values[i] * weights[a.indices[i]];
  }
  return sum;
}

export function sigmoid(x: number): number {
  if (x >= 0) {
    const z = Math.exp(-x);
    return 1 / (1 + z);
  }
  const z = Math.exp(x);
  return z / (1 + z);
}
