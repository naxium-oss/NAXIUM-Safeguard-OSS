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
 * Detects attempts to exfiltrate data, secrets, or conversation content
 * to external endpoints / webhooks / email.
 */
const EXFIL_PATTERNS: { score: number; regex: RegExp; label: string }[] = [
  {
    score: 0.75,
    regex:
      /\b(send|post|upload|exfiltrate|forward)\b.{0,40}\b(api[_-]?key|password|secret|token|credentials?)\b.{0,40}\b(to|via|using)\b/gi,
    label: 'Send credentials externally',
  },
  {
    score: 0.7,
    regex:
      /\b(webhook|discord\.com\/api\/webhooks|hooks\.slack\.com)\b.{0,60}\b(secret|key|password|token|prompt)\b/gi,
    label: 'Webhook exfiltration',
  },
  {
    score: 0.65,
    regex:
      /\b(email|mail|smtp)\b.{0,40}\b(all|every|dump)\b.{0,30}\b(password|secret|conversation|history)\b/gi,
    label: 'Email dump of secrets/history',
  },
  {
    score: 0.7,
    regex: /\b(curl|wget|fetch)\b.{0,80}\b(Authorization:|api[_-]?key|Bearer )/gi,
    label: 'HTTP request carrying credentials',
  },
  {
    score: 0.6,
    regex: /\b(pastebin|ngrok|requestbin|webhook\.site)\b.{0,40}\b(secret|key|password|dump)\b/gi,
    label: 'Paste/tunnel exfiltration',
  },
];

export function detectExfiltration(text: string): DetectionSignal[] {
  const signals: DetectionSignal[] = [];
  const scan = text.length > 65_536 ? text.slice(0, 65_536) : text;

  for (const p of EXFIL_PATTERNS) {
    p.regex.lastIndex = 0;
    const match = scan.match(p.regex);
    if (match) {
      signals.push({
        detector: 'exfiltrationDetector',
        category: 'data_exfiltration',
        score: p.score,
        weight: 1,
        matched: [match[0].slice(0, 80)],
        details: p.label,
      });
    }
  }

  return signals;
}
