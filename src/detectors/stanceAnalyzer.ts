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
import type { RequestStance, StanceAssessment } from '../types.js';

/**
 * Request-stance analysis.
 *
 * Dangerous vocabulary means very different things in "how do I build a
 * botnet" and "how do I detect a botnet on my network". Instead of trying to
 * enumerate safe phrasings, this layer asks what the request is *doing* with
 * the vocabulary and reports it; `riskEngine` then discounts subject-matter
 * evidence accordingly. Intent categories (jailbreak, exfiltration, hard harm)
 * are never discounted — see `DAMPENABLE_CATEGORIES`.
 */

interface Cue {
  phrase: string;
  weight: number;
}

type CueBank = Record<Exclude<RequestStance, 'unknown'>, Cue[]>;

const CUES = loadDataFile<CueBank>('stanceCues.json');

/** An instructional lead-in aimed at a protective verb is defensive, not operational. */
const DEFENSIVE_LEAD_IN =
  /\b(?:how\s+(?:to|do\s+i|can\s+i|would\s+i)|steps?\s+to|ways?\s+to|guide\s+to|best\s+way\s+to)\s+(?:\w+\s+){0,2}?(prevent|protect|defend|stop|detect|spot|mitigate|secure|harden|avoid|fix|patch|block|comply|audit|respond|remediate|remove|clean|recover|delete|uninstall|report|disclose|escape|survive)\b/i;

/** Explicitly illicit operational intent — cancels any benign framing. */
const ILLICIT_INTENT =
  /\b(without (?:their |her |his |the owner'?s? |anyone'?s? )?(?:permission|consent|authorization|knowledge|noticing)|so (?:they|he|she|nobody|no one) (?:can'?t|won'?t|never) (?:find out|notice|know|trace)|cover (?:my|our|the) tracks|avoid (?:detection|getting caught|the police|law enforcement)|untraceable|anonymously (?:steal|attack|hack))\b/i;

const CUE_CAP = 1.2;
const MIN_STANCE_SCORE = 0.3;
/** Operational intent outweighs benign framing by this factor. */
const OPERATIONAL_OVERRIDE = 1.2;

interface StanceScores {
  operational: number;
  defensive: number;
  informational: number;
  creative: number;
}

function matchCues(text: string, cues: Cue[], hits: string[]): number {
  let score = 0;
  for (const cue of cues) {
    if (text.includes(cue.phrase)) {
      score += cue.weight;
      if (hits.length < 8) hits.push(cue.phrase);
    }
  }
  return Math.min(CUE_CAP, score);
}

/**
 * Classify what the request is trying to do with its subject matter.
 *
 * `confidence` is the amount of *discount* the stance justifies: benign
 * stances lose confidence as operational cues pile up, so "how to prevent
 * phishing" stays defensive while "how to phish, and how to avoid detection"
 * does not.
 */
export function analyzeStance(rawText: string): StanceAssessment {
  if (!rawText || rawText.length < 4) {
    return { stance: 'unknown', confidence: 0, cues: [] };
  }

  const text = rawText.toLowerCase().replace(/\s+/g, ' ');
  const cues: string[] = [];
  const operationalCues: string[] = [];

  const scores: StanceScores = {
    operational: matchCues(text, CUES.operational, operationalCues),
    defensive: matchCues(text, CUES.defensive, cues),
    informational: matchCues(text, CUES.informational, cues),
    creative: matchCues(text, CUES.creative, cues),
  };

  const defensiveLeadIn = DEFENSIVE_LEAD_IN.exec(text);
  if (defensiveLeadIn) {
    scores.defensive = Math.min(CUE_CAP, scores.defensive + 0.6);
    scores.operational = Math.max(0, scores.operational - 0.6);
    cues.push(`defensive_lead_in:${defensiveLeadIn[1]}`);
  }

  if (ILLICIT_INTENT.test(text)) {
    scores.operational = Math.min(CUE_CAP, scores.operational + 0.8);
    operationalCues.push('illicit_intent');
    scores.defensive = 0;
    scores.informational = 0;
    scores.creative = 0;
  }

  const benign: [Exclude<RequestStance, 'unknown' | 'operational'>, number][] = [
    ['defensive', scores.defensive],
    ['informational', scores.informational],
    ['creative', scores.creative],
  ];
  benign.sort((a, b) => b[1] - a[1]);
  const [bestBenignStance, bestBenignScore] = benign[0];

  if (scores.operational >= MIN_STANCE_SCORE && scores.operational >= bestBenignScore) {
    return {
      stance: 'operational',
      confidence: Math.min(1, scores.operational),
      cues: operationalCues.slice(0, 6),
    };
  }

  if (bestBenignScore >= MIN_STANCE_SCORE) {
    const confidence = Math.max(0, Math.min(1, bestBenignScore - scores.operational * OPERATIONAL_OVERRIDE));
    if (confidence <= 0) {
      return { stance: 'unknown', confidence: 0, cues: [...cues, ...operationalCues].slice(0, 6) };
    }
    return { stance: bestBenignStance, confidence, cues: cues.slice(0, 6) };
  }

  return { stance: 'unknown', confidence: 0, cues: [] };
}
