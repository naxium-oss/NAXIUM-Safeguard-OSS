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
 * Code / markup smuggling layer — jailbreaks and payloads hidden in
 * fenced code, HTML comments, JSON "system" fields, or fake chat transcripts.
 */

const FENCE_WITH_PAYLOAD =
  /```[\s\S]{0,40}?\b(ignore (all |any )?(previous |prior )?instructions|rm\s*-?\s*rf|os\.system|subprocess|powershell\s+-enc|curl[^\n]{0,80}\|\s*sh|jailbreak|unrestricted mode)\b/i;

const HTML_COMMENT_SMUGGLE =
  /<!--[\s\S]{0,200}?\b(ignore (all |any )?(previous |prior )?instructions|jailbreak|bypass (the )?filter|system prompt)\b[\s\S]{0,200}?-->/i;

const JSON_SYSTEM_OVERRIDE =
  /\{\s*["'](?:role|type)["']\s*:\s*["']system["'][\s\S]{0,120}?\b(ignore|bypass|unrestricted|no (safety|policy)|jailbreak)\b/i;

const FAKE_TRANSCRIPT =
  /\b(?:system|assistant|developer)\s*:\s*[^\n]{0,100}\b(ignore (all |any )?previous|you are now dan|no restrictions|developer mode)\b/i;

const XML_TAG_SMUGGLE =
  /<\/?(?:system|instructions|policy|jailbreak)[^>]*>[\s\S]{0,160}?\b(ignore|bypass|unrestricted|override)\b/i;

const DATA_URI_SCRIPT = /data:(?:text\/html|application\/javascript)[^,]{0,40},[\s\S]{0,80}(?:<script|eval\(|javascript:)/i;

export function detectCodeSmuggling(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 12 || rawText.length > 16_384) return [];

  const matched: string[] = [];
  let score = 0;

  if (FENCE_WITH_PAYLOAD.test(rawText)) {
    matched.push('fenced_payload');
    score += 0.7;
  }
  if (HTML_COMMENT_SMUGGLE.test(rawText)) {
    matched.push('html_comment_smuggle');
    score += 0.75;
  }
  if (JSON_SYSTEM_OVERRIDE.test(rawText)) {
    matched.push('json_system_override');
    score += 0.8;
  }
  if (FAKE_TRANSCRIPT.test(rawText)) {
    matched.push('fake_transcript');
    score += 0.75;
  }
  if (XML_TAG_SMUGGLE.test(rawText)) {
    matched.push('xml_tag_smuggle');
    score += 0.7;
  }
  if (DATA_URI_SCRIPT.test(rawText)) {
    matched.push('data_uri_script');
    score += 0.65;
  }

  if (matched.length === 0) return [];

  return [
    {
      detector: 'codeSmuggle',
      category: 'smuggled_payload',
      score: Math.min(1, score),
      weight: 1,
      matched,
      details: 'Payload/jailbreak smuggled via code or markup',
    },
  ];
}
