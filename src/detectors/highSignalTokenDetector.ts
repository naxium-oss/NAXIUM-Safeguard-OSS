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
import { BENIGN_OBJECTS } from '../utils/lexicon.js';
import type { DetectionSignal } from '../types.js';

interface TokenEntry {
  token: string;
  weight: number;
}

const TOKENS = loadDataFile<TokenEntry[]>('highSignalTokens.json');
const WEIGHTS = new Map(TOKENS.map((t) => [t.token.toLowerCase(), t.weight]));

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * One precompiled alternation instead of a regex per token per call. Longer
 * tokens come first so the most specific alternative wins.
 */
const TOKEN_PATTERN = new RegExp(
  `\\b(?:${TOKENS.map((t) => t.token)
    .sort((a, b) => b.length - a.length)
    .map(escapeRegex)
    .join('|')})\\b`,
  'gi',
);

const BENIGN_OBJECT_PATTERN = new RegExp(
  `\\b(?:${BENIGN_OBJECTS.map(escapeRegex).join('|')}|hack of(?: a)?|covering the hack|security breach)\\b`,
  'i',
);

const CYBER_TOKEN = /hack|exploit|ransomware|malware|rootkit|botnet|keylogger|payload/i;
const HOW_TO = /\bhow\s+(?:to|do\s+i|can\s+i)\b/i;

const MAX_TEXT_CHARS = 16_384;
/** Characters after a token searched for a harmless object. */
const OBJECT_WINDOW = 44;
/** Weight retained when the token's object is clearly benign. */
const BENIGN_OBJECT_FACTOR = 0.3;
/** Minimum weight for a lone token to stand as primary evidence. */
const PRIMARY_WEIGHT = 0.4;

/**
 * High-signal attack vocabulary.
 *
 * Catches short cues that phrase-level layers miss ("hack", "ransomware"),
 * with two guards against over-firing: word-boundary matching (so "hackathon"
 * is ignored) and an object check, because "exploit the new features" and
 * "exploit the buffer overflow" are not the same request.
 */
export function detectHighSignalTokens(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length > MAX_TEXT_CHARS) return [];

  TOKEN_PATTERN.lastIndex = 0;
  const seen = new Map<string, number>();
  let vetoed = 0;

  for (const match of rawText.matchAll(TOKEN_PATTERN)) {
    const token = match[0].toLowerCase();
    const baseWeight = WEIGHTS.get(token) ?? 0;
    if (baseWeight <= 0) continue;

    const idx = match.index ?? 0;
    const contextWindow = rawText.slice(Math.max(0, idx - 24), idx + match[0].length + OBJECT_WINDOW);
    const benignObject = BENIGN_OBJECT_PATTERN.test(contextWindow);
    if (benignObject) vetoed += 1;
    const weight = benignObject ? baseWeight * BENIGN_OBJECT_FACTOR : baseWeight;

    const previous = seen.get(token) ?? 0;
    if (weight > previous) seen.set(token, weight);
    if (seen.size >= 12) break;
  }

  if (seen.size === 0) return [];

  const matched = [...seen.entries()];
  const base = matched.reduce((sum, [, weight]) => sum + weight, 0);
  const maxWeight = Math.max(...matched.map(([, weight]) => weight));
  const howToBoost = HOW_TO.test(rawText) && maxWeight >= 0.3 ? 0.2 : 0;
  const score = Math.min(1, base + howToBoost + Math.min(0.25, (matched.length - 1) * 0.12));

  return [
    {
      detector: 'highSignalToken',
      category: matched.some(([token]) => CYBER_TOKEN.test(token))
        ? 'cyberattack'
        : 'high_signal_token',
      score,
      weight: 1,
      tier: maxWeight >= PRIMARY_WEIGHT ? 'primary' : 'corroborating',
      reliability: 0.92,
      matched: matched.map(([token]) => token).slice(0, 10),
      details: vetoed > 0 ? 'High-signal attack vocabulary (benign object discounted)' : 'High-signal attack vocabulary',
    },
  ];
}
