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
import { describe, it, expect } from 'vitest';
import { shouldRequireApiKey } from '../src/utils/shouldRequireApiKey.js';

describe('shouldRequireApiKey', () => {
  it('requires key in production by default', () => {
    expect(shouldRequireApiKey({ NODE_ENV: 'production' })).toBe(true);
  });

  it('does not require key in development by default', () => {
    expect(shouldRequireApiKey({ NODE_ENV: 'development' })).toBe(false);
  });

  it('honors NAXIUM_REQUIRE_API_KEY=0 override in production', () => {
    expect(shouldRequireApiKey({ NODE_ENV: 'production', NAXIUM_REQUIRE_API_KEY: '0' })).toBe(false);
    expect(shouldRequireApiKey({ NODE_ENV: 'production', NAXIUM_REQUIRE_API_KEY: 'false' })).toBe(false);
  });

  it('honors NAXIUM_REQUIRE_API_KEY=1 in development', () => {
    expect(shouldRequireApiKey({ NODE_ENV: 'development', NAXIUM_REQUIRE_API_KEY: '1' })).toBe(true);
  });
});
