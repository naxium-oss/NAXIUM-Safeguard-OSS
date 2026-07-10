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
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Shallow-safe deep merge for config objects. Arrays and non-plain values are replaced. */
export function deepMerge<T extends Record<string, unknown>>(base: T, override: Partial<T>): T {
  const result: Record<string, unknown> = { ...base };

  for (const key of Object.keys(override) as (keyof T & string)[]) {
    if (DANGEROUS_KEYS.has(key)) continue;
    const next = override[key];
    if (next === undefined) continue;

    const prev = result[key];
    if (isPlainObject(prev) && isPlainObject(next)) {
      result[key] = deepMerge(prev, next as Record<string, unknown>);
    } else {
      result[key] = next;
    }
  }

  return result as T;
}
