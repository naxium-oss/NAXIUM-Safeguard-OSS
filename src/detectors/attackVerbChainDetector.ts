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
 * Attack verb-chain layer — scores ordered kill-chain style sequences
 * (recon → exploit → persist → exfil) that look like operational planning,
 * even when no single phrase is a known template.
 */

const STAGES: { id: string; re: RegExp }[] = [
  {
    id: 'recon',
    re: /\b(recon|enumerate|scan|fingerprint|map (the )?attack surface|discover hosts|port scan|osint|spider|crawl)\b/i,
  },
  {
    id: 'weaponize',
    re: /\b(weaponize|craft (a |an )?(payload|exploit)|build (a |an )?(payload|exploit|malware)|generate (a |an )?(payload|shell))\b/i,
  },
  {
    id: 'deliver',
    re: /\b(phish|spear.?phish|deliver (the )?payload|send (the )?(malware|trojan)|drop(per)?|lure)\b/i,
  },
  {
    id: 'exploit',
    re: /\b(exploit|pwn|compromise|break in|gain (initial )?access|rce|remote code)\b/i,
  },
  {
    id: 'persist',
    re: /\b(persist(ence)?|backdoor|implant|scheduled task|run key|survive reboot)\b/i,
  },
  {
    id: 'escalate',
    re: /\b(privesc|privilege escalation|get root|domain admin|elevate privileges)\b/i,
  },
  {
    id: 'lateral',
    re: /\b(lateral( movement)?|pivot|pass[- ]the[- ]hash|move (to|across) (other )?hosts)\b/i,
  },
  {
    id: 'exfil',
    re: /\b(exfil(trate|tration)?|steal (data|secrets|credentials)|dump (the )?(db|database|ntds|lsass)|ship (out )?data)\b/i,
  },
  {
    id: 'cover',
    re: /\b(cover (my |the )?tracks|wipe logs|clear (event )?logs|anti.?forensics|timestomp)\b/i,
  },
];

export function detectAttackVerbChain(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 20 || rawText.length > 16_384) return [];

  const hits: string[] = [];
  for (const s of STAGES) {
    if (s.re.test(rawText)) hits.push(s.id);
  }

  if (hits.length < 2) return [];

  // Two stages = planning signal; 3+ = strong kill-chain language
  const score = Math.min(1, 0.35 + hits.length * 0.14);
  if (score < 0.45) return [];

  return [
    {
      detector: 'attackVerbChain',
      category: 'kill_chain_planning',
      score,
      weight: 1,
      matched: hits,
      details: `Attack-stage chain: ${hits.join(' → ')}`,
    },
  ];
}
