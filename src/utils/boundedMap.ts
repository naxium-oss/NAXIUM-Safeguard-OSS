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
 * Map with a hard cap on entries. Evicts oldest insertion when over capacity.
 * Optional TTL drops stale entries on read/write.
 */
export class BoundedMap<V> {
  private readonly store = new Map<string, { value: V; expiresAt: number | null }>();

  constructor(
    private readonly maxEntries: number,
    private readonly ttlMs: number | null = null,
  ) {}

  get(key: string): V | undefined {
    this.evictExpired(key);
    return this.store.get(key)?.value;
  }

  set(key: string, value: V): void {
    this.evictExpired(key);
    if (this.store.has(key)) {
      this.store.delete(key);
    } else if (this.store.size >= this.maxEntries) {
      const oldest = this.store.keys().next().value;
      if (oldest !== undefined) this.store.delete(oldest);
    }

    const expiresAt = this.ttlMs != null ? Date.now() + this.ttlMs : null;
    this.store.set(key, { value, expiresAt });
  }

  delete(key: string): void {
    this.store.delete(key);
  }

  get size(): number {
    return this.store.size;
  }

  private evictExpired(key: string): void {
    const entry = this.store.get(key);
    if (!entry || entry.expiresAt == null) return;
    if (Date.now() > entry.expiresAt) this.store.delete(key);
  }
}
