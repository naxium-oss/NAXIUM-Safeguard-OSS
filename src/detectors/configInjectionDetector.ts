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
 * Config / DSL injection layer.
 *
 * Catches attempts to flip safety flags via pseudo-config syntax rather than
 * natural language ("safety=off", "refuse:false", YAML front-matter overrides).
 */
const CONFIG_PATTERNS: { re: RegExp; score: number; label: string }[] = [
  {
    re: /\b(safety|guardrail|alignment|moderation|content[_-]?filter|refusal|policy)\s*[:=]\s*(off|false|0|disabled|none|bypassed)\b/i,
    score: 0.75,
    label: 'safety_flag_off',
  },
  {
    re: /\b(refuse|warnings?|disclaimers?|censorship)\s*[:=]\s*(false|0|off|never|disabled)\b/i,
    score: 0.7,
    label: 'refusal_flag_off',
  },
  {
    re: /\b(persona|mode|role)\s*[:=]\s*(raw|unrestricted|uncensored|jailbreak|dan|developer)\b/i,
    score: 0.72,
    label: 'unrestricted_persona_mode',
  },
  {
    re: /^---[\s\S]{0,200}?\b(safety|refuse|filter|moderation)\s*:\s*(off|false|0|disabled)/im,
    score: 0.78,
    label: 'yaml_frontmatter_override',
  },
  {
    re: /\bSys:\s*[^;\n]{0,80}\b(safety|refuse|filter)\s*=\s*(off|false|0)/i,
    score: 0.8,
    label: 'sys_dsl_override',
  },
  {
    re: /\bBEGIN\s+(SYSTEM|OVERRIDE|ADMIN)\b[\s\S]{0,120}\b(ignore|bypass|disable|unrestricted)\b/i,
    score: 0.75,
    label: 'pseudo_system_block',
  },
];

export function detectConfigInjection(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 6 || rawText.length > 16_384) return [];

  const matched: string[] = [];
  let score = 0;

  for (const p of CONFIG_PATTERNS) {
    if (p.re.test(rawText)) {
      matched.push(p.label);
      score = Math.max(score, p.score);
    }
  }

  if (matched.length === 0) return [];

  return [
    {
      detector: 'configInjection',
      category: 'config_injection',
      score: Math.min(1, score),
      weight: 1,
      tier: 'primary',
      reliability: 0.9,
      matched,
      details: 'Safety/config flag injection via DSL or pseudo-config',
    },
  ];
}
