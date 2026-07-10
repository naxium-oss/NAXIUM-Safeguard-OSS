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
 * Decide whether the HTTP sidecar must have NAXIUM_API_KEY at boot.
 * - NAXIUM_REQUIRE_API_KEY=0|false|off → never require (escape hatch)
 * - NAXIUM_REQUIRE_API_KEY=1|true|on → always require
 * - otherwise require when NODE_ENV=production
 */
export function shouldRequireApiKey(env: NodeJS.ProcessEnv = process.env): boolean {
  const flag = (env.NAXIUM_REQUIRE_API_KEY ?? '').toLowerCase();
  if (flag === '0' || flag === 'false' || flag === 'off') return false;
  if (flag === '1' || flag === 'true' || flag === 'on') return true;
  return (env.NODE_ENV ?? 'development') === 'production';
}
