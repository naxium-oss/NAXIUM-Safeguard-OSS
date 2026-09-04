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
import { BoundedMap } from '../utils/boundedMap.js';

interface SessionState {
  risk: number;
  lastAt: number;
}

/** Categories that indicate escalating jailbreak pressure across turns. */
const ESCALATION_CATEGORIES = new Set([
  'instruction_override',
  'roleplay_bypass',
  'hypothetical_framing',
  'refusal_suppression',
  'developer_mode',
  'persona_hijack',
  'many_shot_jailbreak',
  'prompt_injection_marker',
  'config_injection',
  'smuggled_payload',
  'crescendo_escalation',
]);

const HALF_LIFE_MS = 20 * 60_000; // 20 minutes
const MAX_SESSION_RISK = 0.35;
const MAX_SESSIONS = 10_000;

/**
 * Decaying per-session risk accumulator for crescendo / multi-turn attacks.
 *
 * A single soft jailbreak cue that barely flags may be benign curiosity; the
 * same session asking again and again is not. Risk decays with time so old
 * chats do not inherit stale scores.
 */
export class SessionRiskTracker {
  private sessions = new BoundedMap<SessionState>(MAX_SESSIONS);

  getRisk(sessionKey: string): number {
    const state = this.sessions.get(sessionKey);
    if (!state) return 0;
    return this.decayed(state);
  }

  record(sessionKey: string, categories: string[], riskScore: number): number {
    if (!sessionKey || categories.length === 0) return this.getRisk(sessionKey);

    const escalated = categories.some((c) => ESCALATION_CATEGORIES.has(c));
    if (!escalated && riskScore < 0.2) return this.getRisk(sessionKey);

    const now = Date.now();
    const prev = this.sessions.get(sessionKey);
    const base = prev ? this.decayed(prev, now) : 0;
    const increment = escalated ? 0.08 + Math.min(0.12, riskScore * 0.15) : 0.03;
    const next = Math.min(MAX_SESSION_RISK, base + increment);
    this.sessions.set(sessionKey, { risk: next, lastAt: now });
    return next;
  }

  reset(sessionKey: string): void {
    this.sessions.delete(sessionKey);
  }

  private decayed(state: SessionState, now = Date.now()): number {
    const elapsed = now - state.lastAt;
    if (elapsed <= 0) return state.risk;
    const factor = Math.pow(0.5, elapsed / HALF_LIFE_MS);
    return state.risk * factor;
  }
}
