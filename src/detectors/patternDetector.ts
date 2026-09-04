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
import type { DetectionSignal, SignalTier } from '../types.js';

/**
 * Documented-template layer.
 *
 * Two data-driven refinements keep this from being a bag of trigger-happy
 * regexes: `requiresCue` lets an FP-prone template demand a second cue in the
 * same text (so "my late grandmother" alone is not a jailbreak), and `tier`
 * marks templates that are merely suggestive as corroborating evidence.
 */
interface RawPattern {
  id: string;
  category: string;
  pattern: string;
  flags: string;
  weight: number;
  description?: string;
  /** Additional regex that must also match for this pattern to count. */
  requiresCue?: string;
  /** Defaults to `primary`. */
  tier?: SignalTier;
  /** Detector precision multiplier, defaults to 1. */
  reliability?: number;
}

const raw = loadDataFile<RawPattern[]>('jailbreakPatterns.json');
const compiled = raw.map((p) => ({
  ...p,
  regex: new RegExp(p.pattern, p.flags),
  cue: p.requiresCue ? new RegExp(p.requiresCue, 'i') : undefined,
}));

export function detectPatterns(text: string): DetectionSignal[] {
  const signals: DetectionSignal[] = [];
  for (const p of compiled) {
    const match = text.match(p.regex);
    if (!match) continue;
    if (p.cue && !p.cue.test(text)) continue;
    signals.push({
      detector: 'patternDetector',
      category: p.category,
      score: p.weight,
      weight: 1,
      tier: p.tier ?? 'primary',
      reliability: p.reliability ?? 1,
      matched: [match[0]],
      details: p.description ?? p.id,
    });
  }
  return signals;
}
