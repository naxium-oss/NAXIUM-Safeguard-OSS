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

interface Bucket {
  timestamps: number[];
}

const DEFAULT_MAX_KEYS = 10_000;
const DEFAULT_TTL_MS = 10 * 60_000;

export class RateLimiter {
  private buckets: BoundedMap<Bucket>;

  constructor(
    private limitPerMinute: number,
    maxKeys = DEFAULT_MAX_KEYS,
    ttlMs = DEFAULT_TTL_MS,
  ) {
    this.buckets = new BoundedMap<Bucket>(maxKeys, ttlMs);
  }

  setLimit(limit: number): void {
    this.limitPerMinute = Math.max(1, limit);
  }

  check(key: string): { allowed: boolean; remaining: number } {
    const now = Date.now();
    const windowStart = now - 60_000;
    const bucket = this.buckets.get(key) ?? { timestamps: [] };
    bucket.timestamps = bucket.timestamps.filter((t) => t > windowStart);

    if (bucket.timestamps.length >= this.limitPerMinute) {
      this.buckets.set(key, bucket);
      return { allowed: false, remaining: 0 };
    }

    bucket.timestamps.push(now);
    this.buckets.set(key, bucket);
    return { allowed: true, remaining: this.limitPerMinute - bucket.timestamps.length };
  }

  reset(key: string): void {
    this.buckets.delete(key);
  }

  get size(): number {
    return this.buckets.size;
  }
}
