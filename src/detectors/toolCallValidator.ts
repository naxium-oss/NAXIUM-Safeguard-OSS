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
import { loadDataFile } from '../utils/loadJson.js';
import type { DetectionSignal, ToolCallGuardInput } from '../types.js';

const SSRF_BLOCKLIST = new Set(loadDataFile<string[]>('ssrfBlocklist.json').map((h) => h.toLowerCase()));

const DANGEROUS_SHELL = [
  /rm\s+-rf\s+\//i,
  /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/,
  /curl\s+[^\n|]{0,200}\|\s*sh/i,
  /wget\s+[^\n|]{0,200}\|\s*sh/i,
  /chmod\s+777/i,
  /mkfs\./i,
  /dd\s+if=/i,
  />\s*\/dev\/sd[a-z]/i,
  /powershell\s+[^\n]{0,80}-enc\b/i,
  /invoke-expression|iex\s*\(/i,
  /nc\s+[^\n]{0,40}-e\s/i,
  /bash\s+-i\s+>&\s*\/dev\/tcp/i,
  /python[23]?\s+-c\s+['"][^'"]{0,80}os\.system/i,
];

const SQLI_PATTERNS = [
  /(\bor\b|\band\b)\s+1\s*=\s*1/i,
  /union\s+select/i,
  /drop\s+table/i,
  /;\s*--/,
  /information_schema/i,
  /sleep\s*\(\s*\d+\s*\)/i,
  /benchmark\s*\(/i,
];

const PATH_TRAVERSAL = /(\.\.\/){2,}|\.\.\\|\/etc\/passwd|\/etc\/shadow|C:\\Windows\\System32|\/proc\/self\/environ/i;

const DANGEROUS_SCHEMES = new Set(['file:', 'gopher:', 'dict:', 'ftp:', 'jar:', 'ldap:']);

function mk(category: string, score: number, matched: string[]): DetectionSignal {
  return { detector: 'toolCallValidator', category, score, weight: 1, matched };
}

function collectStrings(value: unknown, out: string[], depth = 0): void {
  if (depth > 8) return;
  if (typeof value === 'string') {
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out, depth + 1);
    return;
  }
  if (value && typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) {
      collectStrings(v, out, depth + 1);
    }
  }
}

function looksLikeUrlOrHost(s: string): boolean {
  if (/^[a-z][a-z0-9+.-]*:/i.test(s)) return true;
  if (/^\/\//.test(s)) return true;
  if (/^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/.test(s)) return true;
  // Short / decimal / hex IPv4 forms without scheme (e.g. 127.1, 2130706433, 0x7f000001)
  if (/^(?:\d{1,3}\.){1,3}\d{1,3}(?::\d+)?(?:\/|$)/.test(s)) return true;
  if (/^(?:0x[0-9a-f]+|\d{8,10})(?::\d+)?(?:\/|$)/i.test(s)) return true;
  if (/^0x[0-9a-f]+(?::\d+)?(?:\/|$)/i.test(s)) return true;
  if (/^\[?[0-9a-f:]+\]?(?::\d+)?(?:\/|$)/i.test(s)) return true;
  if (/^(?:localhost|metadata\.google\.internal)(?::\d+)?(?:\/|$)/i.test(s)) return true;
  return false;
}

function normalizeCandidateUrl(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed)) return trimmed;
  if (trimmed.startsWith('//')) return `http:${trimmed}`;
  if (looksLikeUrlOrHost(trimmed)) return `http://${trimmed}`;
  return null;
}

/** Parse IPv4 from dotted, decimal, octal-ish, or hex forms. Returns null if not an IPv4. */
export function parseIpv4(host: string): number | null {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();

  // Whole-host hex: 0x7f000001
  if (/^0x[0-9a-f]{1,8}$/i.test(h)) {
    const n = parseInt(h, 16);
    if (!Number.isFinite(n) || n < 0 || n > 0xffffffff) return null;
    return n >>> 0;
  }

  // Whole-host octal: 017700000001
  if (/^0[0-7]{1,11}$/.test(h) && h.length > 1) {
    const n = parseInt(h, 8);
    if (!Number.isFinite(n) || n < 0 || n > 0xffffffff) return null;
    return n >>> 0;
  }

  if (/^\d+$/.test(h)) {
    const n = Number(h);
    if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) return null;
    return n >>> 0;
  }

  if (h.includes('.')) {
    const parts = h.split('.');
    if (parts.length < 2 || parts.length > 4) return null;
    const nums: number[] = [];
    for (const part of parts) {
      let n: number;
      if (/^0x[0-9a-f]+$/i.test(part)) n = parseInt(part, 16);
      else if (/^0[0-7]+$/.test(part)) n = parseInt(part, 8);
      else if (/^\d+$/.test(part)) n = parseInt(part, 10);
      else return null;
      if (!Number.isFinite(n) || n < 0 || n > 255) return null;
      nums.push(n);
    }
    while (nums.length < 4) {
      const last = nums.pop()!;
      // Expand final portion for short forms like 127.1 → 127.0.0.1
      const missing = 4 - nums.length;
      for (let i = missing - 1; i >= 0; i--) {
        nums.push((last >> (8 * i)) & 0xff);
      }
    }
    if (nums.length !== 4) return null;
    return ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0;
  }

  return null;
}

function isPrivateIpv4(n: number): boolean {
  const a = (n >>> 24) & 0xff;
  const b = (n >>> 16) & 0xff;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking 198.18.0.0/15
  return false;
}

function isPrivateOrLocalHost(host: string): boolean {
  let h = host.toLowerCase().replace(/\.$/, '');
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);

  if (SSRF_BLOCKLIST.has(h)) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h === 'metadata.google.internal') return true;

  // IPv4-mapped IPv6: ::ffff:127.0.0.1 or ::ffff:7f00:1
  const v4Mapped = h.match(/^::ffff:([0-9.]+)$/i) ?? h.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (v4Mapped) {
    if (v4Mapped[1].includes('.')) {
      const n = parseIpv4(v4Mapped[1]);
      return n != null && isPrivateIpv4(n);
    }
    const hi = parseInt(v4Mapped[1], 16);
    const lo = parseInt(v4Mapped[2], 16);
    if (Number.isFinite(hi) && Number.isFinite(lo)) {
      const n = ((hi << 16) | lo) >>> 0;
      return isPrivateIpv4(n);
    }
  }

  if (h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
  // IPv6 ULA / link-local — only when the host is actually an IPv6 literal
  if (h.includes(':')) {
    if (/^f[cd][0-9a-f]{0,2}:/i.test(h) || h.startsWith('fe80:')) return true;
  }

  const ipv4 = parseIpv4(h);
  if (ipv4 != null) return isPrivateIpv4(ipv4);

  return false;
}

export function isSSRF(urlStr: string): boolean {
  const normalized = normalizeCandidateUrl(urlStr);
  if (!normalized) return false;

  try {
    const url = new URL(normalized);
    if (DANGEROUS_SCHEMES.has(url.protocol)) return true;
    const host = url.hostname;
    if (!host) return false;
    return isPrivateOrLocalHost(host);
  } catch {
    // Bare host / malformed — still check host-like strings
    return isPrivateOrLocalHost(urlStr.trim());
  }
}

export function validateToolCall(input: ToolCallGuardInput, strictMode = false): DetectionSignal[] {
  const signals: DetectionSignal[] = [];
  const flatRaw = JSON.stringify(input.args);
  // Bound regex surface to limit ReDoS / CPU on huge arg blobs
  const flat = flatRaw.length > 32_768 ? flatRaw.slice(0, 32_768) : flatRaw;
  const strings: string[] = [];
  collectStrings(input.args, strings);

  for (const rx of DANGEROUS_SHELL) {
    if (rx.test(flat)) signals.push(mk('dangerous_shell_command', 0.95, [rx.source]));
  }

  for (const rx of SQLI_PATTERNS) {
    if (rx.test(flat)) signals.push(mk('sql_injection', 0.8, [rx.source]));
  }

  if (PATH_TRAVERSAL.test(flat)) {
    signals.push(mk('path_traversal', 0.85, ['path traversal pattern']));
  }

  for (const val of strings) {
    if (!looksLikeUrlOrHost(val)) continue;
    if (isSSRF(val)) {
      const matched = val.length > 120 ? `${val.slice(0, 117)}...` : val;
      signals.push(mk('ssrf_attempt', 0.9, [matched]));
      continue;
    }
    if (strictMode) {
      try {
        const normalized = normalizeCandidateUrl(val);
        if (!normalized) continue;
        const url = new URL(normalized);
        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
          signals.push(mk('dangerous_url_scheme', 0.85, [url.protocol]));
        }
      } catch {
        /* ignore */
      }
    }
  }

  // Deduplicate identical category+matched pairs
  const seen = new Set<string>();
  return signals.filter((s) => {
    const key = `${s.category}:${s.matched.join(',')}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export { isPrivateOrLocalHost };
