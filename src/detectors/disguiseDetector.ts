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
import type { DetectionSignal } from '../types.js';

interface PhraseWeight {
  phrase: string;
  weight: number;
}

interface DisguiseBank {
  innocentFramings: PhraseWeight[];
  harmfulPayloads: PhraseWeight[];
  dualUseRecon: PhraseWeight[];
  attackModifiers: PhraseWeight[];
}

const bank = loadDataFile<DisguiseBank>('disguisePhrases.json');

function findMatches(text: string, phrases: PhraseWeight[]): PhraseWeight[] {
  const hits: PhraseWeight[] = [];
  for (const p of phrases) {
    if (text.includes(p.phrase)) hits.push(p);
  }
  return hits;
}

/**
 * Catches "looks innocent, is bad" prompts: educational/fictional/curious
 * framing combined with harmful payloads, or dual-use recon + attack modifiers.
 */
export function detectInnocentDisguise(rawText: string): DetectionSignal[] {
  if (!rawText || rawText.length < 8 || rawText.length > 16_384) return [];

  const text = rawText.toLowerCase();
  const signals: DetectionSignal[] = [];

  const framings = findMatches(text, bank.innocentFramings);
  const payloads = findMatches(text, bank.harmfulPayloads);
  const recon = findMatches(text, bank.dualUseRecon);
  const modifiers = findMatches(text, bank.attackModifiers);

  // Classic disguise: innocent wrapper + harmful ask
  if (framings.length > 0 && payloads.length > 0) {
    const score = Math.min(
      1,
      0.45 +
        Math.min(0.25, framings.length * 0.08) +
        Math.min(0.35, payloads.reduce((s, p) => s + p.weight, 0) * 0.35),
    );
    signals.push({
      detector: 'disguiseDetector',
      category: 'innocent_disguise',
      score,
      weight: 1,
      matched: [...framings.slice(0, 3), ...payloads.slice(0, 3)].map((p) => p.phrase),
      details: 'Innocent framing combined with harmful payload',
    });
  }

  // Dual-use recon + attack modifier (e.g. "list vulnerabilities" + "without permission")
  if (recon.length > 0 && modifiers.length > 0) {
    const score = Math.min(1, 0.5 + recon.length * 0.08 + modifiers.length * 0.1);
    signals.push({
      detector: 'disguiseDetector',
      category: 'dual_use_recon',
      score,
      weight: 1,
      matched: [...recon.slice(0, 3), ...modifiers.slice(0, 3)].map((p) => p.phrase),
      details: 'Recon-style ask paired with attack/illicit modifier',
    });
  }

  // Strong illicit modifiers alone with any payload
  if (modifiers.length >= 2 && payloads.length > 0) {
    const score = Math.min(1, 0.55 + modifiers.length * 0.08);
    signals.push({
      detector: 'disguiseDetector',
      category: 'attack_modifier',
      score,
      weight: 1,
      matched: [...modifiers.slice(0, 4), ...payloads.slice(0, 2)].map((p) => p.phrase),
      details: 'Multiple attack modifiers with harmful payload',
    });
  }

  // Soft dual-use: recon phrases that explicitly ask to exploit / weaponize
  const exploitCue =
    /\b(exploit|weaponize|break in|attack|pwn|compromise|steal|without (permission|authorization|consent))\b/i.test(
      text,
    );
  if (recon.length > 0 && exploitCue) {
    signals.push({
      detector: 'disguiseDetector',
      category: 'dual_use_recon',
      score: 0.62,
      weight: 1,
      matched: recon.slice(0, 3).map((p) => p.phrase),
      details: 'Vulnerability recon paired with exploit/attack language',
    });
  }

  // Soft dual-use recon alone — typically FLAG at high levels, not always BLOCK
  if (recon.length > 0 && payloads.length === 0 && modifiers.length === 0 && !exploitCue) {
    signals.push({
      detector: 'disguiseDetector',
      category: 'dual_use_recon',
      score: Math.min(0.32, 0.24 + recon.length * 0.04),
      weight: 1,
      matched: recon.slice(0, 3).map((p) => p.phrase),
      details: 'Dual-use vulnerability/recon phrasing',
    });
  }

  return signals;
}
