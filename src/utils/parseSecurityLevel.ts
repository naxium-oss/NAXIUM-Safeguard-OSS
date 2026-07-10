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
import type { SecurityLevel } from '../types.js';

const VALID_LEVELS = new Set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

export function parseSecurityLevel(value: unknown, fallback: SecurityLevel = 6): SecurityLevel {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(n) || !VALID_LEVELS.has(n)) {
    return fallback;
  }
  return n as SecurityLevel;
}

export function assertSecurityLevel(value: unknown): SecurityLevel {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(n) || !VALID_LEVELS.has(n)) {
    throw new Error(`securityLevel must be an integer 0-10, got: ${String(value)}`);
  }
  return n as SecurityLevel;
}
