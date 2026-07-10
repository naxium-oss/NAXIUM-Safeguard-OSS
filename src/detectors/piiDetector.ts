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

const EMAIL = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const PHONE = /\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
const SSN = /\b\d{3}-\d{2}-\d{4}\b/g;
const CREDIT_CARD = /\b(?:\d[ -]*?){13,19}\b/g;
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

function luhnCheck(num: string): boolean {
  const digits = num.replace(/\D/g, '');
  if (digits.length < 13) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function sig(category: string, matched: string[], score: number): DetectionSignal {
  return { detector: 'piiDetector', category, score, weight: 1, matched: matched.slice(0, 5) };
}

export function detectPII(text: string, strict: boolean): DetectionSignal[] {
  const signals: DetectionSignal[] = [];
  const scan = text.length > 65_536 ? text.slice(0, 65_536) : text;

  const emails = scan.match(EMAIL);
  if (emails) signals.push(sig('pii_email', emails, strict ? 0.3 : 0.15));

  const ssns = scan.match(SSN);
  if (ssns) signals.push(sig('pii_ssn', ssns, 0.7));

  const cards = (scan.match(CREDIT_CARD) ?? []).filter(luhnCheck);
  if (cards.length) signals.push(sig('pii_credit_card', cards, 0.75));

  if (strict) {
    const phones = scan.match(PHONE);
    if (phones) signals.push(sig('pii_phone', phones, 0.2));

    const ips = scan.match(IPV4);
    if (ips) signals.push(sig('pii_ip', ips, 0.1));
  }

  return signals;
}
