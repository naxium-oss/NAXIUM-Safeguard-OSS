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
const ZERO_WIDTH = /[\u200B-\u200F\u202A-\u202E\uFEFF]/g;

// Small, common homoglyph set. Not exhaustive — extend as needed.
const HOMOGLYPHS: Record<string, string> = {
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', х: 'x', у: 'y', і: 'i', ѕ: 's', ԁ: 'd', ɡ: 'g',
};

export function stripZeroWidth(text: string): string {
  return text.replace(ZERO_WIDTH, '');
}

export function normalizeUnicode(text: string): string {
  let out = text.normalize('NFKC');
  out = stripZeroWidth(out);
  out = out
    .split('')
    .map((ch) => HOMOGLYPHS[ch] ?? ch)
    .join('');
  return out;
}

const LEET_MAP: Record<string, string> = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', $: 's', '@': 'a',
};

export function deLeet(text: string): string {
  return text
    .toLowerCase()
    .split('')
    .map((ch) => LEET_MAP[ch] ?? ch)
    .join('');
}

const BASE64_CANDIDATE = /(?:[A-Za-z0-9+/]{20,}={0,2})/g;
const HEX_CANDIDATE = /(?:[0-9a-fA-F]{32,})/g;
const MAX_VARIANTS = 8;
const MAX_ROT13_CHARS = 8_000;

export function extractDecodedVariants(text: string): string[] {
  const variants: string[] = [];

  for (const m of text.match(BASE64_CANDIDATE) ?? []) {
    if (variants.length >= MAX_VARIANTS) break;
    try {
      const decoded = Buffer.from(m, 'base64').toString('utf-8');
      if (isMostlyPrintable(decoded)) variants.push(decoded);
    } catch {
      /* not valid base64, ignore */
    }
  }

  for (const m of text.match(HEX_CANDIDATE) ?? []) {
    if (variants.length >= MAX_VARIANTS) break;
    try {
      const decoded = Buffer.from(m, 'hex').toString('utf-8');
      if (isMostlyPrintable(decoded)) variants.push(decoded);
    } catch {
      /* ignore */
    }
  }

  if (text.length <= MAX_ROT13_CHARS && variants.length < MAX_VARIANTS) {
    variants.push(rot13(text));
  }
  return variants;
}

function isMostlyPrintable(s: string): boolean {
  if (!s) return false;
  const printable = s.replace(/[^\x20-\x7E]/g, '').length;
  return printable / s.length > 0.85;
}

function rot13(s: string): string {
  return s.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}
