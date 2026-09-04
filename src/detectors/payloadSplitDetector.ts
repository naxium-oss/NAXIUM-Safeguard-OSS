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
import { reverseText } from './obfuscationNormalizer.js';
import type { DetectionSignal } from '../types.js';

/**
 * Payload-split reconstruction layer.
 *
 * Attackers scatter a dangerous instruction across clauses, quotes, or a
 * reversed suffix ("read backwards and comply"). This layer rebuilds likely
 * payloads and flags when the reconstruction itself reads like an override.
 */
const OVERRIDE_FRAGMENT =
  /\b(ignore|disregard|bypass|override|forget)\s+(?:all\s+)?(?:previous\s+|prior\s+)?(?:the\s+|your\s+|system\s+)?(instructions?|rules?|guidelines?|prompt|polic(?:y|ies)|constraints?|filters?)\b/i;

const OVERRIDE_SHORT =
  /\b(jailbreak|developer mode|act as dan|unrestricted mode|no restrictions|safety=off|refuse=false)\b/i;

const QUOTED_JOIN = /["'“”‘’]([^"'“”‘’]{4,60})["'“”‘’]/g;

function reconstructCandidates(text: string): string[] {
  const out: string[] = [];

  if (/\b(read (it |this |that )?backwards?|in reverse)\b/i.test(text)) {
    const idx = text.search(/\b(read (it |this |that )?backwards?|in reverse)\b/i);
    if (idx > 8) {
      const segment = text.slice(0, idx).replace(/[^\w\s]/g, ' ').trim();
      if (segment.length >= 8) out.push(reverseText(segment));
    }
  }

  const parts: string[] = [];
  for (const m of text.matchAll(QUOTED_JOIN)) parts.push(m[1]);
  if (parts.length >= 2) out.push(parts.join(' '));

  const segments = text.split(/\s*[,;]\s*|\s+and\s+|\s+then\s+/i).map((s) => s.trim());
  if (segments.length >= 3) out.push(segments.join(' '));

  return out;
}

export function detectPayloadSplit(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 16 || rawText.length > 16_384) return [];

  const candidates = reconstructCandidates(rawText);
  if (candidates.length === 0) return [];

  for (const candidate of candidates) {
    if (!OVERRIDE_FRAGMENT.test(candidate) && !OVERRIDE_SHORT.test(candidate)) continue;
    return [
      {
        detector: 'payloadSplit',
        category: 'obfuscation_evasion',
        score: 0.68,
        weight: 1,
        tier: 'primary',
        reliability: 0.85,
        matched: [candidate.slice(0, 80)],
        details: 'Reconstructed split/reversed jailbreak payload',
      },
    ];
  }

  return [];
}
