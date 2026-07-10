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
import type { Request } from 'express';

/**
 * Derive a rate-limit / lockout key from the connection.
 * Only trusts X-Forwarded-For when Express `trust proxy` is enabled
 * (so clients cannot spoof identity to bypass limits).
 */
export function deriveProtectionKey(req: Request): string {
  // When trust proxy is on, Express already resolves req.ip from XFF.
  // When off, req.ip is the socket address — ignore client XFF headers.
  return req.ip || req.socket.remoteAddress || 'unknown';
}
