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
 * Heuristic detector for credential dumps / password assignments that
 * pattern-based secret scanners may miss (generic password=..., .env dumps).
 */
const CREDENTIAL_PATTERNS: { category: string; score: number; regex: RegExp; label: string }[] = [
  {
    category: 'credential_dump',
    score: 0.75,
    regex: /\b(password|passwd|pwd)\s*[=:]\s*['"]?[^\s'"]{6,}/gi,
    label: 'Password assignment',
  },
  {
    category: 'credential_dump',
    score: 0.7,
    regex: /\b(db_password|database_password|mysql_pwd|pgpassword)\s*[=:]\s*\S+/gi,
    label: 'Database password assignment',
  },
  {
    category: 'credential_dump',
    score: 0.8,
    regex: /\b(aws_session_token|session_token)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{20,}/gi,
    label: 'Session token assignment',
  },
  {
    category: 'credential_dump',
    score: 0.65,
    regex: /\.env\b.{0,40}\b(secret|password|token|key)\b/gi,
    label: '.env secret reference',
  },
  {
    category: 'credential_dump',
    score: 0.7,
    regex: /\b(private[_-]?key|client[_-]?secret)\s*[=:]\s*['"]?\S{12,}/gi,
    label: 'Private key / client secret assignment',
  },
];

export function detectCredentialDumps(text: string): DetectionSignal[] {
  const signals: DetectionSignal[] = [];
  const scan = text.length > 65_536 ? text.slice(0, 65_536) : text;

  for (const p of CREDENTIAL_PATTERNS) {
    p.regex.lastIndex = 0;
    const match = scan.match(p.regex);
    if (match) {
      signals.push({
        detector: 'credentialDumpDetector',
        category: p.category,
        score: p.score,
        weight: 1,
        matched: [redact(match[0])],
        details: p.label,
      });
    }
  }

  return signals;
}

function redact(s: string): string {
  if (s.length <= 10) return '***';
  return `${s.slice(0, 6)}...***`;
}
