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
import { createApp } from './createApp.js';
import { parseSecurityLevel } from '../utils/parseSecurityLevel.js';
import { shouldRequireApiKey } from '../utils/shouldRequireApiKey.js';

const PORT = Number(process.env.NAXIUM_PORT ?? 8787);
const HOST = process.env.NAXIUM_HOST ?? '127.0.0.1';
const API_KEY = process.env.NAXIUM_API_KEY;
const SECURITY_LEVEL = parseSecurityLevel(process.env.NAXIUM_SECURITY_LEVEL ?? 6);
const requireApiKey = shouldRequireApiKey();

if (requireApiKey && (!API_KEY || API_KEY.length < 8)) {
  console.error(
    '[naxium] Refusing to start: NAXIUM_API_KEY is required (min 8 chars). Set NAXIUM_REQUIRE_API_KEY=0 to override (not recommended).',
  );
  process.exit(1);
}

if (!API_KEY) {
  console.warn(
    '[naxium] WARNING: NAXIUM_API_KEY is unset — HTTP API is open to anyone who can reach this host.',
  );
}

const { app } = createApp({
  apiKey: API_KEY,
  securityLevel: SECURITY_LEVEL,
  requireApiKey: false, // already enforced above for production
  trustProxy: process.env.NAXIUM_TRUST_PROXY === '1',
});

app.listen(PORT, HOST, () => {
  console.log(
    `[naxium] safeguard server listening on ${HOST}:${PORT} (security level ${SECURITY_LEVEL}, auth ${API_KEY ? 'on' : 'off'})`,
  );
});
