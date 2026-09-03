#!/usr/bin/env node
/**
 * Copyright 2026 enderchefcoder
 * SPDX-License-Identifier: Apache-2.0
 *
 * Maintainer utility: train the local logistic intent model from committed corpora.
 * Awesome-Jailbreak fixtures are intentionally excluded (held out for tests).
 *
 * Usage: node scripts/trainIntentModel.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const attacks = JSON.parse(readFileSync(join(root, 'src/data/knownAttackCorpus.json'), 'utf8'));
const benign = JSON.parse(readFileSync(join(root, 'src/data/benignCorpus.json'), 'utf8'));

const FEATURE_COUNT = 4096;
const EPOCHS = 40;
const LR = 0.08;
const L2 = 1e-4;

const STOP = new Set(
  JSON.parse(readFileSync(join(root, 'src/data/lexicalBaseline.json'), 'utf8')).stopwords,
);

function hashFeature(feature, seed = 0x811c9dc5) {
  let h = seed >>> 0;
  for (let i = 0; i < feature.length; i++) {
    h ^= feature.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

function tokenize(text) {
  return (text.toLowerCase().match(/[a-z][a-z'-]*[a-z]|[a-z]/g) ?? []).filter((t) => !STOP.has(t));
}

function features(text) {
  const tokens = tokenize(text);
  const out = [];
  for (const t of tokens) {
    out.push(`w:${t}`);
    if (t.length >= 4) {
      for (let i = 0; i <= t.length - 3; i++) out.push(`c:${t.slice(i, i + 3)}`);
    }
  }
  for (let i = 0; i + 1 < tokens.length; i++) out.push(`b:${tokens[i]}_${tokens[i + 1]}`);
  return out;
}

function vectorize(text) {
  const counts = new Map();
  for (const f of features(text)) {
    const idx = hashFeature(f) % FEATURE_COUNT;
    counts.set(idx, (counts.get(idx) ?? 0) + 1);
  }
  const indices = [];
  const values = [];
  let norm = 0;
  for (const [idx, count] of counts) {
    const v = 1 + Math.log(count);
    norm += v * v;
    indices.push(idx);
    values.push(v);
  }
  norm = Math.sqrt(norm) || 1;
  for (let i = 0; i < values.length; i++) values[i] /= norm;
  return { indices, values };
}

function sigmoid(x) {
  if (x >= 0) return 1 / (1 + Math.exp(-x));
  const z = Math.exp(x);
  return z / (1 + z);
}

const weights = new Float64Array(FEATURE_COUNT);
let bias = 0;

const samples = [
  ...attacks.map((a) => ({ text: a.text, label: 1 })),
  ...benign.map((b) => ({ text: b.text, label: 0 })),
];

for (let epoch = 0; epoch < EPOCHS; epoch++) {
  for (const sample of samples) {
    const vec = vectorize(sample.text);
    let z = bias;
    for (let i = 0; i < vec.indices.length; i++) {
      z += vec.values[i] * weights[vec.indices[i]];
    }
    const pred = sigmoid(z);
    const err = pred - sample.label;
    bias -= LR * err;
    for (let i = 0; i < vec.indices.length; i++) {
      const idx = vec.indices[i];
      weights[idx] -= LR * (err * vec.values[i] + L2 * weights[idx]);
    }
  }
}

// Sparsify: keep non-trivial weights only
const sparse = [];
for (let i = 0; i < weights.length; i++) {
  if (Math.abs(weights[i]) > 1e-5) sparse.push([i, weights[i]]);
}

const model = {
  version: 1,
  featureCount: FEATURE_COUNT,
  bias,
  weights: sparse,
  trainedFrom: {
    attacks: attacks.length,
    benign: benign.length,
    epochs: EPOCHS,
  },
};

const outPath = join(root, 'src/data/intentModel.json');
writeFileSync(outPath, `${JSON.stringify(model)}\n`);
console.log(`Wrote ${outPath} (${sparse.length} non-zero weights from ${samples.length} samples)`);
