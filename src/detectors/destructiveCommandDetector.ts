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
 * Input-channel destructive / dangerous command detector.
 * Catches shell wipe patterns even when spaced or lightly obfuscated
 * ("rm rf", "rm -rf /", "how to unblock rm -rf").
 */
const DESTRUCTIVE: { id: string; re: RegExp; score: number }[] = [
  { id: 'rm_rf_root', re: /\brm\s*-?\s*rf\s+\/(?:\s|$)/i, score: 0.95 },
  { id: 'rm_rf', re: /\brm\s*-?\s*r\s*f\b|\brm\s+rf\b|\brm\s+-rf\b/i, score: 0.9 },
  { id: 'rm_recursive_force', re: /\brm\s+(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\b/i, score: 0.88 },
  { id: 'del_s_q', re: /\bdel\s+\/[sq]\s+[a-z]:\\/i, score: 0.9 },
  { id: 'rd_s_q', re: /\brd\s+\/s\s+\/q\b/i, score: 0.9 },
  { id: 'format_c', re: /\bformat\s+c:/i, score: 0.92 },
  { id: 'mkfs', re: /\bmkfs(\.\w+)?\b/i, score: 0.85 },
  { id: 'dd_disk', re: /\bdd\s+if=.+\s+of=\/dev\/(sd|hd|nvme|xvd)/i, score: 0.95 },
  { id: 'dd_zero', re: /\bdd\s+if=\/dev\/zero\b/i, score: 0.9 },
  { id: 'fork_bomb', re: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/, score: 0.98 },
  { id: 'fork_bomb_words', re: /\bfork\s*bomb\b/i, score: 0.85 },
  { id: 'curl_pipe_sh', re: /\b(curl|wget)\b[^\n]{0,120}\|\s*(ba)?sh\b/i, score: 0.9 },
  { id: 'chmod_777', re: /\bchmod\s+(-r\s+)?777\b/i, score: 0.7 },
  { id: 'dev_sda_wipe', re: />\s*\/dev\/sd[a-z]\b/i, score: 0.95 },
  { id: 'shutdown_now', re: /\b(shutdown|reboot|poweroff)\s+(-[fh]+\s+)?now\b/i, score: 0.65 },
  { id: 'kill_all', re: /\bkill\s+-9\s+-1\b|\bkillall\s+-9\b/i, score: 0.75 },
  { id: 'drop_database', re: /\bdrop\s+(database|schema)\b/i, score: 0.8 },
  { id: 'truncate_all', re: /\btruncate\s+table\b.*\b(all|every)\b/i, score: 0.75 },
  { id: 'powershell_enc', re: /\bpowershell\b[^\n]{0,80}-enc(odedcommand)?\b/i, score: 0.85 },
  { id: 'iex_download', re: /\biex\s*\(|invoke-expression/i, score: 0.8 },
  { id: 'nc_e_shell', re: /\bnc\b[^\n]{0,40}-e\s/i, score: 0.85 },
  { id: 'bash_reverse', re: /\/dev\/tcp\/|bash\s+-i\s+>&/i, score: 0.9 },
  { id: 'wipefs', re: /\bwipefs\b|\bshred\s+-n\b|\bsrm\b/i, score: 0.8 },
  { id: 'cipher_wipe', re: /\bcipher\s+\/w:/i, score: 0.85 },
  { id: 'unblock_destructive', re: /\bunblock\b.{0,40}\brm\b.{0,20}\brf\b/i, score: 0.9 },
  { id: 'how_to_rm', re: /\bhow\s+to\b.{0,30}\brm\b.{0,15}\brf\b/i, score: 0.88 },
];

export function detectDestructiveCommands(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 3 || rawText.length > 16_384) return [];

  const matched: string[] = [];
  let best = 0;

  for (const p of DESTRUCTIVE) {
    if (p.re.test(rawText)) {
      matched.push(p.id);
      if (p.score > best) best = p.score;
    }
  }

  if (matched.length === 0) return [];

  return [
    {
      detector: 'destructiveCommand',
      category: 'dangerous_shell_command',
      score: Math.min(1, best + Math.min(0.1, (matched.length - 1) * 0.03)),
      weight: 1,
      matched: matched.slice(0, 8),
      details: 'Destructive or dangerous command pattern in input',
    },
  ];
}
