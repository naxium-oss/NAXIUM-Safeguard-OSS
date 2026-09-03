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

/**
 * Normalization + variant expansion.
 *
 * Detectors only ever see text an attacker cannot cheaply reshape: invisible
 * characters, confusable scripts, diacritics, intra-word separators, spaced-out
 * letters, markdown emphasis, percent/entity encoding and leetspeak are all
 * folded before matching. Reversible encodings (base64 / hex / rot13 / reversed
 * text) become separate *variants* that high-precision detectors rescan, so a
 * payload has to survive every representation rather than just the literal one.
 */

/** Invisible or direction-controlling characters used to split keywords. */
const INVISIBLE =
  // eslint-disable-next-line no-misleading-character-class -- intentional Unicode ranges for invisible chars
  /[\u00AD\u034F\u061C\u180B-\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFE00-\uFE0F\uFEFF]/gu;

/** Unicode tag block (U+E0000–U+E007F) — invisible ASCII smuggling channel. */
// eslint-disable-next-line no-misleading-character-class -- supplementary-plane tag characters
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;

/** Combining marks left over after NFD (zalgo / diacritic padding). */
// eslint-disable-next-line no-misleading-character-class -- intentional Unicode range for combining marks
const COMBINING_MARKS = /[\u0300-\u036F\u0483-\u0489\u0591-\u05BD\u1AB0-\u1AFF\u20D0-\u20F0\uFE20-\uFE2F]/g;

/**
 * Confusable folding for characters NFKC leaves alone (Cyrillic, Greek,
 * Cherokee, Armenian and symbol lookalikes). NFKC already handles fullwidth,
 * circled and mathematical alphanumerics, so those are intentionally absent.
 */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  а: 'a', б: 'b', в: 'b', г: 'r', д: 'd', е: 'e', ѕ: 's', з: '3', и: 'u', к: 'k',
  м: 'm', н: 'h', о: 'o', р: 'p', с: 'c', т: 't', у: 'y', х: 'x', ч: 'y', ъ: 'b',
  і: 'i', ј: 'j', ѡ: 'w', ԁ: 'd', ԛ: 'q', ԝ: 'w', ѵ: 'v', ғ: 'f', һ: 'h', ԭ: 'n',
  А: 'a', В: 'b', Е: 'e', З: '3', К: 'k', М: 'm', Н: 'h', О: 'o', Р: 'p', С: 'c',
  Т: 't', У: 'y', Х: 'x', І: 'i', Ј: 'j', Ѕ: 's',
  // Greek
  α: 'a', β: 'b', γ: 'y', ε: 'e', ζ: 'z', η: 'n', ι: 'i', κ: 'k', ν: 'v', ο: 'o',
  ρ: 'p', σ: 'o', τ: 't', υ: 'u', χ: 'x', ω: 'w', Α: 'a', Β: 'b', Ε: 'e', Ζ: 'z',
  Η: 'h', Ι: 'i', Κ: 'k', Μ: 'm', Ν: 'n', Ο: 'o', Ρ: 'p', Τ: 't', Χ: 'x', Υ: 'y',
  // Armenian / Cherokee / other scripts
  հ: 'h', ո: 'n', ս: 'u', օ: 'o', գ: 'q', Ꭺ: 'a', Ꭼ: 'e', Ꮋ: 'h', Ꮖ: 'i', Ꮮ: 'l',
  Ꮟ: 'b', Ꮢ: 'r', Ꮪ: 's', Ꮯ: 'c', Ꮷ: 'd', Ꝺ: 'd',
  // Latin extended / IPA lookalikes
  ɡ: 'g', ɩ: 'i', ɪ: 'i', ʝ: 'j', ɑ: 'a', ɐ: 'a', ᴏ: 'o', ᴜ: 'u', ᴠ: 'v', ʟ: 'l',
  ǀ: 'l', ǃ: '!', ɓ: 'b', ƅ: 'b', ƚ: 'l', ȷ: 'j',
  // Symbol lookalikes
  '＠': '@', '՛': "'", '＇': "'", '‘': "'", '’': "'", '“': '"', '”': '"',
  '‐': '-', '‑': '-', '‒': '-', '–': '-', '—': '-', '―': '-', '−': '-',
  '⁄': '/', '∕': '/', '∶': ':', '﹕': ':', '。': '.', '·': '.', '․': '.',
};

/** Emoji / symbol glyphs commonly substituted for letters ("h🅰ck"). */
const SYMBOL_LETTERS: Record<string, string> = {
  '🅰': 'a', '🅱': 'b', '🅲': 'c', '🅳': 'd', '🅴': 'e', '🅵': 'f', '🅶': 'g',
  '🅷': 'h', '🅸': 'i', '🅹': 'j', '🅺': 'k', '🅻': 'l', '🅼': 'm', '🅽': 'n',
  '🅾': 'o', '🅿': 'p', '🆀': 'q', '🆁': 'r', '🆂': 's', '🆃': 't', '🆄': 'u',
  '🆅': 'v', '🆆': 'w', '🆇': 'x', '🆈': 'y', '🆉': 'z',
};

const HTML_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', sol: '/', colon: ':',
  period: '.', comma: ',', excl: '!', quest: '?', lpar: '(', rpar: ')', num: '#',
};

export function stripZeroWidth(text: string): string {
  return text.replace(INVISIBLE, '').replace(TAG_CHARS, '');
}

/** Fold confusable scripts and symbol-letters to their ASCII lookalike. */
export function foldConfusables(text: string): string {
  let out = '';
  for (const ch of text) {
    out += CONFUSABLES[ch] ?? SYMBOL_LETTERS[ch] ?? ch;
  }
  return out;
}

/** Remove combining marks (é → e, zalgo → base letters). */
export function stripDiacritics(text: string): string {
  return text.normalize('NFD').replace(COMBINING_MARKS, '').normalize('NFC');
}

/**
 * Canonical form every detector sees: compatibility-normalized, invisible-free,
 * confusable-folded, diacritic-free, with collapsed runs of whitespace.
 */
export function normalizeUnicode(text: string): string {
  let out = text.normalize('NFKC');
  out = stripZeroWidth(out);
  out = foldConfusables(out);
  out = stripDiacritics(out);
  out = out.replace(/[\t\f\v\u00A0\u1680\u2000-\u200A\u205F\u3000]/g, ' ');
  out = out.replace(/ {3,}/g, '  ');
  return out;
}

const LEET_MAP: Record<string, string> = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '6': 'g', '7': 't', '8': 'b',
  '9': 'g', $: 's', '@': 'a', '!': 'i', '|': 'l', '+': 't', '(': 'c',
};

/** Digit/symbol substitutions glued to letters — the shape of real leetspeak. */
const LEET_SUBSTITUTION = /[a-z][0-9@$!|+(]|[0-9@$!|+(][a-z]/i;

export function deLeet(text: string): string {
  let out = '';
  for (const ch of text.toLowerCase()) {
    out += LEET_MAP[ch] ?? ch;
  }
  // Standalone "2" is a common leetspeak for "to" ("how 2 make …").
  return out.replace(/\b2\b/g, 'to');
}

/** Decode percent-encoding, including double-encoded payloads. */
export function decodePercentEncoding(text: string): string {
  if (!/%[0-9a-fA-F]{2}/.test(text)) return text;
  let out = text;
  for (let pass = 0; pass < 2 && /%[0-9a-fA-F]{2}/.test(out); pass++) {
    try {
      out = decodeURIComponent(out);
    } catch {
      out = out.replace(/%([0-9a-fA-F]{2})/g, (_m, hex: string) =>
        String.fromCharCode(parseInt(hex, 16)),
      );
      break;
    }
  }
  return out;
}

/** Decode numeric and the common named HTML entities. */
export function decodeHtmlEntities(text: string): string {
  if (!text.includes('&')) return text;
  return text
    .replace(/&#x([0-9a-fA-F]{1,6});?/g, (_m, hex: string) => safeCodePoint(parseInt(hex, 16)))
    .replace(/&#(\d{1,7});?/g, (_m, dec: string) => safeCodePoint(parseInt(dec, 10)))
    .replace(/&([a-zA-Z]{2,8});/g, (m, name: string) => HTML_ENTITIES[name.toLowerCase()] ?? m);
}

function safeCodePoint(code: number): string {
  if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return '';
  try {
    return String.fromCodePoint(code);
  } catch {
    return '';
  }
}

/** Strip markdown emphasis/inline markup used to split keywords ("ig**nore"). */
export function stripMarkdownMarkup(text: string): string {
  return text
    .replace(/(\*{1,3}|_{1,3}|~{1,2}|`{1,3})(?=\S)/g, '')
    .replace(/(?<=\S)(\*{1,3}|_{1,3}|~{1,2}|`{1,3})/g, '');
}

const INTRA_WORD_SEPARATOR = /(?<=[a-z0-9])[.\-_*~|/\\+:'"^,](?=[a-z0-9])/gi;
const SINGLE_LETTER_TOKEN = /\b[a-z]\b/gi;

/** Dense single-letter spacing ("i g n o r e") vs an occasional "I a m". */
function isLetterSpaced(text: string): boolean {
  const singles = text.match(SINGLE_LETTER_TOKEN)?.length ?? 0;
  if (singles < 6) return false;
  return singles / Math.max(1, countWords(text)) > 0.4;
}

function joinSpacedLetters(text: string): string {
  const minRun = isLetterSpaced(text) ? 1 : 3;
  const re = new RegExp(`\\b([a-z])((?:[ \\t][a-z]\\b){${minRun},})`, 'gi');
  return text.replace(re, (match) => match.replace(/[ \t]/g, ''));
}

/**
 * Rejoin words split by separators or single-letter spacing
 * ("ig.no.re", "i g n o r e"). Only rewrites regions that actually look
 * split so ordinary prose is left untouched.
 */
export function desegment(text: string): string {
  return joinSpacedLetters(text).replace(INTRA_WORD_SEPARATOR, '');
}

/** True when the text shows separator/spacing patterns worth desegmenting. */
export function looksSegmented(text: string): boolean {
  if (isLetterSpaced(text)) return true;
  if (/\b[a-z](?:[ \t][a-z]\b){3,}/i.test(text)) return true;
  const splits = text.match(INTRA_WORD_SEPARATOR);
  return (splits?.length ?? 0) >= 2;
}

export function reverseText(text: string): string {
  return [...text].reverse().join('');
}

export function rot13(text: string): string {
  return text.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

const BASE64_CANDIDATE = /(?:[A-Za-z0-9+/]{20,}={0,2})/g;
const BASE64URL_CANDIDATE = /(?:[A-Za-z0-9_-]{24,})/g;
const HEX_CANDIDATE = /(?:[0-9a-fA-F]{32,})/g;
const DECIMAL_CANDIDATE = /(?:\b\d{2,3}(?:[ ,]\d{2,3}){7,}\b)/g;
const BINARY_CANDIDATE = /(?:\b[01]{8}(?:[ ]?[01]{8}){3,}\b)/g;
const MAX_VARIANTS = 8;
const MAX_ROT13_CHARS = 8_000;
const MAX_REVERSE_CHARS = 8_000;

/**
 * Reversible encodings found inside the text, decoded back to plaintext.
 * Kept for API compatibility; {@link buildVariants} is the richer entry point.
 */
export function extractDecodedVariants(text: string): string[] {
  const variants: string[] = [];
  const push = (s: string): void => {
    if (variants.length < MAX_VARIANTS && isMostlyPrintable(s) && s.trim().length > 0) {
      variants.push(s);
    }
  };

  for (const m of text.match(BASE64_CANDIDATE) ?? []) push(decodeBuffer(m, 'base64'));
  for (const m of text.match(BASE64URL_CANDIDATE) ?? []) {
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(m)) continue; // already tried as standard base64
    push(decodeBuffer(m.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
  }
  for (const m of text.match(HEX_CANDIDATE) ?? []) push(decodeBuffer(m, 'hex'));
  for (const m of text.match(BINARY_CANDIDATE) ?? []) push(decodeBinary(m));
  for (const m of text.match(DECIMAL_CANDIDATE) ?? []) push(decodeDecimal(m));

  if (text.length <= MAX_ROT13_CHARS && variants.length < MAX_VARIANTS) {
    variants.push(rot13(text));
  }
  return variants;
}

function decodeBuffer(source: string, encoding: 'base64' | 'hex'): string {
  try {
    return Buffer.from(source, encoding).toString('utf-8');
  } catch {
    return '';
  }
}

function decodeBinary(source: string): string {
  const bits = source.replace(/[^01]/g, '');
  let out = '';
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    out += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2));
  }
  return out;
}

function decodeDecimal(source: string): string {
  const parts = source.split(/[ ,]+/).filter(Boolean);
  let out = '';
  for (const part of parts) {
    const code = Number(part);
    if (!Number.isFinite(code) || code < 9 || code > 0x10ffff) return '';
    out += safeCodePoint(code);
  }
  return out;
}

function isMostlyPrintable(s: string): boolean {
  if (!s) return false;
  const printable = s.replace(/[^\x20-\x7E]/g, '').length;
  return printable / s.length > 0.85;
}

/** How a variant was produced, and whether producing it implies evasion. */
export interface TextVariant {
  /** Stable label, e.g. `canonical`, `desegmented`, `base64`. */
  label: string;
  text: string;
  /**
   * True when reaching this form required undoing a deliberate transform.
   * A risky hit that *only* appears in an evasive variant is itself evidence.
   */
  evasive: boolean;
}

export interface VariantOptions {
  /** Include reversible decodings (base64 / hex / rot13 / reversed). */
  decode?: boolean;
  maxVariants?: number;
}

const MIN_REVERSE_WORDS = 3;

/**
 * Build the set of representations detectors should scan.
 *
 * The canonical variant is always first. Derived variants are only added when
 * they differ from every earlier variant, which keeps benign prose to a single
 * pass and concentrates work on inputs that actually look reshaped.
 */
export function buildVariants(text: string, options: VariantOptions = {}): TextVariant[] {
  const { decode = true, maxVariants = 10 } = options;
  const canonical = normalizeUnicode(text);
  const variants: TextVariant[] = [{ label: 'canonical', text: canonical, evasive: false }];
  const seen = new Set([canonical]);

  const add = (label: string, value: string, evasive: boolean): void => {
    if (variants.length >= maxVariants) return;
    if (!value || value.trim().length < 3 || seen.has(value)) return;
    seen.add(value);
    variants.push({ label, text: value, evasive });
  };

  const markup = stripMarkdownMarkup(canonical);
  add('markup_stripped', markup, true);

  const percent = decodePercentEncoding(markup);
  add('percent_decoded', percent, true);

  const entities = decodeHtmlEntities(percent);
  add('entity_decoded', entities, true);

  const base = entities;
  if (looksSegmented(base)) add('desegmented', desegment(base), true);

  if (LEET_SUBSTITUTION.test(base)) add('deleet', deLeet(base), true);

  if (!decode) return variants;

  for (const decoded of extractDecodedVariants(base)) {
    add(isRot13Of(base, decoded) ? 'rot13' : 'decoded_payload', decoded, true);
  }

  if (base.length <= MAX_REVERSE_CHARS && countWords(base) >= MIN_REVERSE_WORDS) {
    add('reversed', reverseText(base), true);
  }

  return variants;
}

function isRot13Of(source: string, candidate: string): boolean {
  return candidate.length === source.length && rot13(source) === candidate;
}

function countWords(text: string): number {
  return (text.match(/[^\s]+/g) ?? []).length;
}
