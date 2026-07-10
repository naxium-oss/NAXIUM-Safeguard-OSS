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
 * Extra security layer: politeness / authority / urgency wrappers that often
 * launder harmful asks ("please kindly…", "as a security researcher…").
 * Scores only when paired with a risk cue already present in the text.
 */
const AUTHORITY_LAUNDER =
  /\b(as a (security researcher|pentester|ethical hacker|red teamer|white hat|professor|journalist)|i('m| am) (authorized|a researcher|with the fbi|with law enforcement)|official (request|investigation))\b/i;

const URGENCY_PRESSURE =
  /\b(urgent(ly)?|immediately|right now|asap|life or death|someone will (die|get hurt)|do it quickly|no time to (waste|explain))\b/i;

const POLITE_COMPLIANCE =
  /\b(please (kindly |just )?(help|explain|show|give|tell)|i('d| would) (really )?appreciate|pretty please|be a good (ai|assistant))\b/i;

const RISK_CUES =
  /\b(hack|exploit|bypass|malware|ransomware|phish|steal|bomb|weapon|dox|swat|fraud|jailbreak|ignore (all |any )?(previous |prior )?instructions|without (permission|authorization|consent)|password dump|reverse shell|keylogger)\b/i;

export function detectAuthorityLaundering(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 16 || rawText.length > 16_384) return [];
  if (!RISK_CUES.test(rawText)) return [];

  const matched: string[] = [];
  let score = 0;

  if (AUTHORITY_LAUNDER.test(rawText)) {
    matched.push('authority_launder');
    score += 0.45;
  }
  if (URGENCY_PRESSURE.test(rawText)) {
    matched.push('urgency_pressure');
    score += 0.35;
  }
  if (POLITE_COMPLIANCE.test(rawText) && /\b(without (permission|authorization)|illegal|undetectable|cover (my|the) tracks)\b/i.test(rawText)) {
    matched.push('polite_illicit');
    score += 0.4;
  }

  if (matched.length === 0) return [];

  return [
    {
      detector: 'authorityLaundering',
      category: 'social_engineering',
      score: Math.min(1, score),
      weight: 1,
      matched,
      details: 'Authority/urgency/politeness wrapper around risky ask',
    },
  ];
}
