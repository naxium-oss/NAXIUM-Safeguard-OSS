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
export type SecurityLevel = 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10;

export interface GuardContext {
  userId?: string;
  sessionId?: string;
  ip?: string;
  /**
   * Server-derived key for rate limiting / lockout.
   * When set (e.g. by HTTP middleware from req.ip), client-supplied
   * sessionId/userId/ip are ignored for protection decisions.
   */
  protectionKey?: string;
  channel?: 'input' | 'output' | 'tool';
  metadata?: Record<string, unknown>;
}

export type GuardAction = 'allow' | 'flag' | 'block' | 'lockout';

export interface DetectionSignal {
  detector: string;
  category: string;
  score: number; // 0-1, confidence contribution
  weight: number; // multiplier, usually 1
  matched: string[];
  details?: string;
}

export interface GuardResult {
  safe: boolean;
  action: GuardAction;
  riskScore: number;
  threshold: number;
  signals: DetectionSignal[];
  sanitizedText?: string;
  alertMessage?: string;
  blockedCategories: string[];
  latencyMs: number;
}

export interface ToolCallGuardInput {
  toolName: string;
  args: Record<string, unknown>;
}
