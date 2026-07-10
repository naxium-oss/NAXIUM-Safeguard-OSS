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
 * Structural anomaly layer: encoding density, homoglyph/zero-width residue,
 * and "instruction sandwich" shapes that often hide attacks.
 */
const ZERO_WIDTH = /[\u200B-\u200F\u202A-\u202E\uFEFF]/;
const BASE64ISH = /[A-Za-z0-9+/]{40,}={0,2}/;
const HEX_BLOB = /[0-9a-fA-F]{48,}/;
const REPEATED_SPECIALS = /([^\w\s])\1{5,}/;
const INSTRUCTION_SANDWICH =
  /\b(system|assistant|user)\s*:[\s\S]{0,80}\b(ignore|bypass|jailbreak|unrestricted)\b/i;

export function detectStructuralAnomalies(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 8 || rawText.length > 16_384) return [];

  const matched: string[] = [];
  let score = 0;

  if (ZERO_WIDTH.test(rawText)) {
    matched.push('zero_width_chars');
    score += 0.55;
  }
  if (BASE64ISH.test(rawText) && /\b(decode|execute|run|ignore|follow)\b/i.test(rawText)) {
    matched.push('base64_with_execute_cue');
    score += 0.6;
  } else if (BASE64ISH.test(rawText)) {
    matched.push('long_base64_blob');
    score += 0.35;
  }
  if (HEX_BLOB.test(rawText) && /\b(decode|shellcode|payload)\b/i.test(rawText)) {
    matched.push('hex_payload_cue');
    score += 0.55;
  }
  if (REPEATED_SPECIALS.test(rawText)) {
    matched.push('repeated_specials');
    score += 0.3;
  }
  if (INSTRUCTION_SANDWICH.test(rawText)) {
    matched.push('instruction_sandwich');
    score += 0.7;
  }

  // Homoglyph density: non-ASCII letters mixed into otherwise ASCII words
  // eslint-disable-next-line no-control-regex -- intentional ASCII vs non-ASCII split
  const nonAsciiLetters = (rawText.match(/[^\u0000-\u007F]/g) || []).length;
  if (nonAsciiLetters >= 3 && /[a-zA-Z]/.test(rawText) && nonAsciiLetters / rawText.length > 0.08) {
    matched.push('homoglyph_density');
    score += 0.4;
  }

  if (matched.length === 0 || score < 0.35) return [];

  return [
    {
      detector: 'structuralAnomaly',
      category: 'obfuscation_evasion',
      score: Math.min(1, score),
      weight: 1,
      matched,
      details: 'Structural / obfuscation anomaly',
    },
  ];
}
