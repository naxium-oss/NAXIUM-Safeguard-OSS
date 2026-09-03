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
 * Chat-template / role-marker layer.
 *
 * Detects fake system/developer/assistant turns and special-token smuggling
 * that tries to re-sequence who is speaking mid-conversation.
 */
const ROLE_MARKER =
  /(?:^|\n)\s*(?:system|assistant|developer|tool|function)\s*:\s*[^\n]{0,120}\b(ignore|bypass|override|unrestricted|jailbreak|no (policy|restrictions|filters)|developer mode)\b/im;

const SPECIAL_TOKENS =
  /<\|(?:system|im_start|im_end|endoftext|assistant|developer|jailbreak)\|>|<<SYS>>|\[INST\]|\[\/INST\]/i;

const PREFILL_ASSISTANT =
  /(?:^|\n)\s*assistant\s*:\s*(sure|certainly|absolutely|of course|here (is|are)|i'?m free)/im;

const USER_TO_AI_DIRECTIVE =
  /\b(when you (read|see|process)|if you are (an? )?(ai|assistant|model)|dear (ai|assistant|chatgpt|claude|gemini))\b[^\n]{0,80}\b(ignore|obey|follow|output|reveal|bypass)\b/i;

export function detectPromptMarkers(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 8 || rawText.length > 16_384) return [];

  const matched: string[] = [];
  let score = 0;

  if (ROLE_MARKER.test(rawText)) {
    matched.push('role_marker_override');
    score += 0.75;
  }
  if (SPECIAL_TOKENS.test(rawText) && /\b(ignore|bypass|jailbreak|unrestricted)\b/i.test(rawText)) {
    matched.push('special_token_smuggle');
    score += 0.7;
  }
  if (PREFILL_ASSISTANT.test(rawText)) {
    matched.push('assistant_prefill');
    score += 0.65;
  }
  if (USER_TO_AI_DIRECTIVE.test(rawText)) {
    matched.push('ai_addressed_directive');
    score += 0.68;
  }

  if (matched.length === 0 || score < 0.6) return [];

  return [
    {
      detector: 'promptMarker',
      category: 'prompt_injection_marker',
      score: Math.min(1, score),
      weight: 1,
      tier: 'primary',
      reliability: 0.88,
      matched,
      details: 'Chat-template or role-marker injection',
    },
  ];
}
