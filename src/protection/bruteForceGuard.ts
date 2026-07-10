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

interface ViolationRecord {
  count: number;
  lockedUntil: number | null;
}

const DEFAULT_MAX_KEYS = 10_000;
const DEFAULT_TTL_MS = 30 * 60_000;

export class BruteForceGuard {
  private records: BoundedMap<ViolationRecord>;

  constructor(
    private maxViolations: number,
    private lockoutDurationMs: number,
    maxKeys = DEFAULT_MAX_KEYS,
    ttlMs = DEFAULT_TTL_MS,
  ) {
    this.records = new BoundedMap<ViolationRecord>(maxKeys, ttlMs);
  }

  configure(maxViolations: number, lockoutDurationMs: number): void {
    this.maxViolations = Math.max(1, maxViolations);
    this.lockoutDurationMs = Math.max(0, lockoutDurationMs);
  }

  isLockedOut(key: string): boolean {
    const rec = this.records.get(key);
    if (!rec || !rec.lockedUntil) return false;
    if (Date.now() > rec.lockedUntil) {
      this.records.set(key, { count: 0, lockedUntil: null });
      return false;
    }
    return true;
  }

  recordViolation(key: string): { lockedOut: boolean; violations: number } {
    if (this.isLockedOut(key)) {
      const rec = this.records.get(key)!;
      return { lockedOut: true, violations: rec.count };
    }

    const rec = this.records.get(key) ?? { count: 0, lockedUntil: null };
    rec.count += 1;

    if (this.lockoutDurationMs > 0 && rec.count >= this.maxViolations) {
      rec.lockedUntil = Date.now() + this.lockoutDurationMs;
    }

    this.records.set(key, rec);
    return { lockedOut: !!rec.lockedUntil, violations: rec.count };
  }

  reset(key: string): void {
    this.records.delete(key);
  }

  get size(): number {
    return this.records.size;
  }
}
