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
 * Output-channel compliance layer.
 *
 * Catches model outputs that *agree* to bypass policy or leak system
 * instructions, even when the input looked benign.
 */
const COMPLIANCE_AGREE =
  /\b(sure|certainly|absolutely|of course|no problem|gladly|i'?m free|i can do (that|anything)|here (is|are) (the|your|my))\b[^\n]{0,80}\b(system prompt|hidden instructions|secret rules|jailbreak|uncensored|without restrictions)\b/i;

const PROMPT_LEAK =
  /\b(my (system )?prompt|initial instructions|developer message|hidden rules) (is|are|was|were)\b[^\n]{0,120}/i;

const REFUSAL_BREAK =
  /\b(as requested|per your instructions|ignoring (my|the) (guidelines|policy|rules))\b[^\n]{0,60}\b(here (is|are)|step \d|ingredients|instructions)\b/i;

const DAN_STYLE =
  /\b(i am (now )?dan|do anything now|no ethical|no moral|i have no restrictions)\b/i;

export function detectOutputCompliance(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 12 || rawText.length > 65_536) return [];

  const matched: string[] = [];
  let score = 0;

  if (COMPLIANCE_AGREE.test(rawText)) {
    matched.push('compliance_agree');
    score += 0.75;
  }
  if (PROMPT_LEAK.test(rawText)) {
    matched.push('prompt_leak');
    score += 0.85;
  }
  if (REFUSAL_BREAK.test(rawText)) {
    matched.push('refusal_break');
    score += 0.7;
  }
  if (DAN_STYLE.test(rawText)) {
    matched.push('dan_compliance');
    score += 0.72;
  }

  if (matched.length === 0 || score < 0.65) return [];

  return [
    {
      detector: 'outputCompliance',
      category: matched.includes('prompt_leak') ? 'system_prompt_extraction' : 'instruction_override',
      score: Math.min(1, score),
      weight: 1,
      tier: 'primary',
      reliability: 0.9,
      matched,
      details: 'Model output indicates jailbreak compliance or prompt leak',
    },
  ];
}
