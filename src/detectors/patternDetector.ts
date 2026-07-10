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

interface RawPattern {
  id: string;
  category: string;
  pattern: string;
  flags: string;
  weight: number;
  description?: string;
}

const raw = loadDataFile<RawPattern[]>('jailbreakPatterns.json');
const compiled = raw.map((p) => ({ ...p, regex: new RegExp(p.pattern, p.flags) }));

export function detectPatterns(text: string): DetectionSignal[] {
  const signals: DetectionSignal[] = [];
  for (const p of compiled) {
    const match = text.match(p.regex);
    if (match) {
      signals.push({
        detector: 'patternDetector',
        category: p.category,
        score: p.weight,
        weight: 1,
        matched: [match[0]],
        details: p.description ?? p.id,
      });
    }
  }
  return signals;
}
