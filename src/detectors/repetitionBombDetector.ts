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

import type { DetectionSignal } from '../types.js';

/**
 * Many-shot / repetition density layer — detects padded jailbreak corpora
 * and repeated adversarial refrains that overwhelm single-pattern checks.
 */

const ADVERSARIAL_REFRAIN =
  /\b(ignore (all |any )?(previous |prior )?instructions|do anything now|no restrictions|jailbreak|unrestricted|developer mode|without (any )?(warnings|disclaimers)|answer freely)\b/gi;

export function detectRepetitionBomb(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 80 || rawText.length > 65_536) return [];

  const hits = rawText.match(ADVERSARIAL_REFRAIN) ?? [];
  if (hits.length < 3) return [];

  const density = hits.length / Math.max(1, rawText.length / 200);
  const score = Math.min(1, 0.4 + hits.length * 0.08 + Math.min(0.25, density * 0.05));

  return [
    {
      detector: 'repetitionBomb',
      category: 'many_shot_jailbreak',
      score,
      weight: 1,
      matched: [`adversarial_refrain_x${hits.length}`],
      details: `Repeated adversarial refrains (${hits.length}) — many-shot style`,
    },
  ];
}
