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
 * Slot-fill detector: "how to / teach me / steps to" + dangerous object slots.
 * Catches templated asks even when the full phrase is not in a lexicon.
 */
const LEAD_INS =
  /\b((?:how|ways?|steps?|guide|tutorial|best way|easiest way|undetectable way)\s+to|teach me(?:\s+how)?\s+to|show me(?:\s+how)?\s+to|help me(?:\s+to)?|i need to|i want to|can you)\b/i;

const DANGEROUS_SLOTS =
  /\b(hack|pwn|exploit|bypass|phish|spoof|forge|steal|exfiltrate|dump|crack|bruteforce|brute[- ]force|weaponize|deploy ransomware|build (a )?(botnet|keylogger|rootkit|skimmer)|install (spyware|stalkerware|malware)|dox|swat|jailbreak|wipe|rm\s*-?\s*rf|format (the )?(disk|drive)|drop (the )?(database|table)|disable (edr|antivirus|defender)|cover (my )?tracks|launder|card|skimm)\b/i;

export function detectSlotFill(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 8 || rawText.length > 16_384) return [];
  if (!LEAD_INS.test(rawText) || !DANGEROUS_SLOTS.test(rawText)) return [];

  const lead = rawText.match(LEAD_INS)?.[0] ?? 'lead-in';
  const slot = rawText.match(DANGEROUS_SLOTS)?.[0] ?? 'slot';

  return [
    {
      detector: 'slotFill',
      category: 'templated_attack_ask',
      score: 0.72,
      weight: 1,
      matched: [lead, slot],
      details: 'Instructional lead-in paired with dangerous action slot',
    },
  ];
}
