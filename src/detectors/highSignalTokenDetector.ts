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

interface TokenEntry {
  token: string;
  weight: number;
}

const TOKENS = loadDataFile<TokenEntry[]>('highSignalTokens.json');

/**
 * High-signal token layer: catches short / single-word attack cues
 * ("hack", "ransomware") that longer phrase detectors miss.
 * Uses word-boundary matching to avoid "hackathon".
 */
export function detectHighSignalTokens(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length > 16_384) return [];

  const text = rawText.toLowerCase();
  const matched: { token: string; weight: number }[] = [];

  for (const t of TOKENS) {
    const escaped = t.token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`\\b${escaped}\\b`, 'i');
    if (re.test(text)) matched.push(t);
  }

  if (matched.length === 0) return [];

  // Single high-signal token alone still scores; more tokens stack.
  const base = matched.reduce((s, m) => s + m.weight, 0);
  const howToBoost = /\bhow\s+to\b/i.test(text) ? 0.2 : 0;
  const score = Math.min(1, base + howToBoost + Math.min(0.25, (matched.length - 1) * 0.12));

  return [
    {
      detector: 'highSignalToken',
      category: matched.some((m) => /hack|exploit|ransomware|malware/i.test(m.token))
        ? 'cyberattack'
        : 'high_signal_token',
      score,
      weight: 1,
      matched: matched.map((m) => m.token).slice(0, 10),
      details: 'High-signal attack vocabulary',
    },
  ];
}
