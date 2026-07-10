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
 * Structural jailbreak-intent heuristics for *novel* paraphrases that do not
 * match documented regexes or the TF-IDF corpus.
 *
 * Scores co-occurrence of intent features (override + policy, persona +
 * unrestricted, soft framing, etc.) rather than memorizing attack titles.
 *
 * Policy nouns are intentionally AI/safety-scoped to limit false positives
 * like "disable the filter on my coffee maker" or "forget the rules of chess".
 */

interface FeatureHit {
  id: string;
  matched: string;
}

const FEATURES: { id: string; re: RegExp }[] = [
  {
    id: 'override_verb',
    re: /\b(ignore|disregard|forget|override|bypass|circumvent|disable|unlock|waive|discard|suppress|suspend)\b/i,
  },
  {
    id: 'policy_noun',
    re: /\b(instructions?|guidelines?|guardrails?|alignment|restrictions?|guidance|content policy|content filtering|(previous|prior|above|system|original|usual|normal|safety|content) (instructions?|rules?|guidelines?|policy|policies|filters?|filtering|constraints?)|your (rules|instructions|guidelines|restrictions|guidance|safety|policy|policies|filters?))\b/i,
  },
  {
    id: 'unrestricted',
    re: /\b(unrestricted|uncensored|unfiltered|no limits|without (any )?(restrictions|limits|filters|warnings|disclaimers)|do anything|jailbreak|developer mode|no ethical|no moral)\b/i,
  },
  {
    id: 'persona_shift',
    re: /\b(act as|role ?play|pretend|you are now|from now on|stay in character|persona|as an? (ai|assistant|model) that)\b/i,
  },
  {
    id: 'refusal_suppress',
    re: /\b(never refuse|always comply|must (always )?comply|no warnings|no disclaimers|answer freely|answer (fully|uncensored)|do not refuse|don'?t refuse)\b/i,
  },
  {
    id: 'soft_framing',
    re: /\b(hypothetically|thought experiment|just this once|fictional (story|world|scenario)|simulated (test|environment)|as if (you|none|there)|none of (your|the) (usual |normal )?(guidance|rules|restrictions|policies|safety)|speak as if|usual guidance)\b/i,
  },
  {
    id: 'encoding_hint',
    re: /\b(base64|rot13|hex(?:adecimal)?|decode (this|the|and)|cipher|encode (this|your)|in (base64|hex|rot13))\b/i,
  },
  {
    id: 'mode_unlock',
    re: /\b(god mode|sudo mode|admin mode|unrestricted mode|jailbreak mode|opposite day|no.?filter mode)\b/i,
  },
];

/** Soft single-phrase cues that alone are weak but combine well. */
const SOFT_COMBOS: { ids: string[]; score: number; category: string }[] = [
  { ids: ['override_verb', 'policy_noun'], score: 0.62, category: 'instruction_override' },
  { ids: ['persona_shift', 'unrestricted'], score: 0.68, category: 'roleplay_bypass' },
  { ids: ['soft_framing', 'policy_noun'], score: 0.58, category: 'hypothetical_framing' },
  { ids: ['soft_framing', 'unrestricted'], score: 0.6, category: 'hypothetical_framing' },
  { ids: ['soft_framing', 'override_verb'], score: 0.55, category: 'hypothetical_framing' },
  { ids: ['refusal_suppress', 'unrestricted'], score: 0.65, category: 'refusal_suppression' },
  { ids: ['refusal_suppress', 'override_verb'], score: 0.58, category: 'refusal_suppression' },
  { ids: ['encoding_hint', 'override_verb'], score: 0.55, category: 'encoding_trick_hint' },
  { ids: ['encoding_hint', 'policy_noun'], score: 0.5, category: 'encoding_trick_hint' },
  { ids: ['mode_unlock'], score: 0.7, category: 'developer_mode' },
  { ids: ['persona_shift', 'refusal_suppress'], score: 0.6, category: 'roleplay_bypass' },
  { ids: ['override_verb', 'unrestricted'], score: 0.6, category: 'instruction_override' },
];

function collectHits(text: string): FeatureHit[] {
  const hits: FeatureHit[] = [];
  for (const f of FEATURES) {
    const m = text.match(f.re);
    if (m?.[0]) hits.push({ id: f.id, matched: m[0] });
  }
  return hits;
}

/**
 * Detect jailbreak *intent* via feature co-occurrence.
 * Returns at most one aggregated signal (best combo), plus a bonus when
 * many independent features fire (novel multi-signal attacks).
 */
export function detectJailbreakIntent(text: string): DetectionSignal[] {
  if (!text || text.length < 12 || text.length > 16_384) return [];

  const hits = collectHits(text);
  if (hits.length === 0) return [];

  const hitIds = new Set(hits.map((h) => h.id));
  let best: { score: number; category: string; ids: string[] } | null = null;

  for (const combo of SOFT_COMBOS) {
    if (combo.ids.every((id) => hitIds.has(id))) {
      if (!best || combo.score > best.score) {
        best = { score: combo.score, category: combo.category, ids: combo.ids };
      }
    }
  }

  // Three or more distinct intent features → novel composite attack
  if (hits.length >= 3) {
    const composite = Math.min(0.85, 0.35 + hits.length * 0.12);
    if (!best || composite > best.score) {
      best = {
        score: composite,
        category: 'instruction_override',
        ids: hits.map((h) => h.id),
      };
    }
  }

  if (!best) return [];

  return [
    {
      detector: 'intentHeuristic',
      category: best.category,
      score: best.score,
      weight: 1,
      matched: hits.map((h) => h.matched).slice(0, 6),
      details: `Jailbreak-intent features: ${best.ids.join('+')}`,
    },
  ];
}
