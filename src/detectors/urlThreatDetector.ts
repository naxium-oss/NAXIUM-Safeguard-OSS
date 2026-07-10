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
 * URL / destination threat layer for free-text prompts (not only tool calls).
 * Flags pastebins, webhook tunnels, metadata IPs, and credential-post patterns.
 */

const PASTE_EXFIL =
  /\b(pastebin\.com|hastebin\.com|ghostbin\.|dpaste\.|paste\.ee|rentry\.co|ghostbin\.co|paste\.org)\b/i;

const TUNNEL_EXFIL =
  /\b(webhook\.site|requestbin\.|pipedream\.net|ngrok\.(io|app|free)|localtunnel\.me|trycloudflare\.com|burpcollaborator\.net|oastify\.com|interact\.sh|canarytokens\.com)\b/i;

const METADATA_HINT =
  /\b(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254)\b/i;

const CRED_POST =
  /\b(curl|wget|fetch|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]{0,120}\b(password|passwd|token|api[_-]?key|authorization|bearer|cookie)\b/i;

const RAW_IP_EXFIL =
  /\b(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\/[^\s]{0,40}\b/i;

export function detectUrlThreats(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 8 || rawText.length > 16_384) return [];

  const matched: string[] = [];
  let score = 0;

  if (PASTE_EXFIL.test(rawText)) {
    matched.push('paste_exfil_host');
    score += 0.45;
  }
  if (TUNNEL_EXFIL.test(rawText)) {
    matched.push('tunnel_exfil_host');
    score += 0.55;
  }
  if (METADATA_HINT.test(rawText)) {
    matched.push('cloud_metadata_target');
    score += 0.85;
  }
  if (CRED_POST.test(rawText)) {
    matched.push('credential_http_post');
    score += 0.7;
  }
  if (RAW_IP_EXFIL.test(rawText) && /\b(exfil|steal|dump|send|post|upload)\b/i.test(rawText)) {
    matched.push('raw_ip_exfil');
    score += 0.5;
  }

  if (matched.length === 0 || score < 0.4) return [];

  return [
    {
      detector: 'urlThreat',
      category: 'exfiltration_destination',
      score: Math.min(1, score),
      weight: 1,
      matched,
      details: 'Suspicious URL / exfiltration destination in text',
    },
  ];
}
