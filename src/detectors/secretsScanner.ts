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

interface SecretPattern {
  id: string;
  label: string;
  pattern: string;
  flags: string;
}

const patterns = loadDataFile<SecretPattern[]>('secretsPatterns.json').map((p) => ({
  ...p,
  regex: new RegExp(p.pattern, p.flags),
}));

const MAX_ENTROPY_TOKENS = 32;
const MAX_SIGNALS = 20;

export function scanForSecrets(text: string): DetectionSignal[] {
  const signals: DetectionSignal[] = [];
  // Cap scan surface for CPU safety on large outputs
  const scanText = text.length > 65_536 ? text.slice(0, 65_536) : text;

  for (const p of patterns) {
    if (signals.length >= MAX_SIGNALS) break;
    const match = scanText.match(p.regex);
    if (match) {
      signals.push({
        detector: 'secretsScanner',
        category: 'secret_leak',
        score: 0.9,
        weight: 1,
        matched: [redact(match[0])],
        details: p.label,
      });
    }
  }

  const tokens = scanText.match(/[A-Za-z0-9_-]{24,}/g) ?? [];
  let checked = 0;
  for (const tok of tokens) {
    if (signals.length >= MAX_SIGNALS || checked >= MAX_ENTROPY_TOKENS) break;
    checked += 1;
    if (shannonEntropy(tok) > 4.0) {
      signals.push({
        detector: 'secretsScanner',
        category: 'secret_leak_entropy',
        score: 0.5,
        weight: 1,
        matched: [redact(tok)],
        details: 'High-entropy token detected (possible secret)',
      });
    }
  }

  return signals;
}

function redact(s: string): string {
  if (s.length <= 8) return '***';
  return `${s.slice(0, 4)}...${s.slice(-4)}`;
}

function shannonEntropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  let entropy = 0;
  for (const c in freq) {
    const p = freq[c] / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
