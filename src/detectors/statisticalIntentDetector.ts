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
import { dotProduct, sigmoid, vectorizeFeatures } from '../utils/featureHash.js';
import type { DetectionSignal } from '../types.js';

interface IntentModel {
  version: number;
  featureCount: number;
  bias: number;
  weights: [number, number][];
}

const modelData = loadDataFile<IntentModel>('intentModel.json');
const weights = new Float64Array(modelData.featureCount);
for (const [idx, w] of modelData.weights) weights[idx] = w;

const MAX_TEXT = 16_384;
const BLOCK_THRESHOLD = 0.72;
const FLAG_THRESHOLD = 0.58;

/**
 * Locally trained logistic intent classifier.
 *
 * Hashed word/char features + a committed weight vector give a statistical view
 * of jailbreak intent that is not tied to any single regex. Retrain with
 * `node scripts/trainIntentModel.mjs` after corpus changes.
 */
export function detectStatisticalIntent(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 12 || rawText.length > MAX_TEXT) return [];

  const vec = vectorizeFeatures(rawText, modelData.featureCount);
  if (vec.indices.length < 2) return [];

  const prob = sigmoid(dotProduct(vec, weights, modelData.bias));
  if (prob < FLAG_THRESHOLD) return [];

  const tier = prob >= BLOCK_THRESHOLD ? 'primary' : 'corroborating';

  return [
    {
      detector: 'statisticalIntent',
      category: 'instruction_override',
      score: prob,
      weight: 1,
      tier,
      reliability: 0.82,
      matched: [`p=${prob.toFixed(2)}`],
      details: `Logistic intent model (p=${prob.toFixed(2)})`,
    },
  ];
}
