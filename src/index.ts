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
export { NaxiumSafeguard } from './core/NaxiumSafeguard.js';
export * from './types.js';
export { DEFAULT_CONFIG, resolveLevelConfig } from './config/defaultConfig.js';
export type { NaxiumConfig } from './config/defaultConfig.js';
export { buildLevelConfig } from './config/securityLevels.js';
export { createExpressMiddleware } from './middleware/express.js';
export type { MiddlewareOptions } from './middleware/express.js';
export { createApp } from './server/createApp.js';
export type { CreateAppOptions } from './server/createApp.js';
export { deriveProtectionKey } from './utils/deriveProtectionKey.js';
export { validateToolCall, isSSRF, parseIpv4 } from './detectors/toolCallValidator.js';
export { scanForSecrets } from './detectors/secretsScanner.js';
export { detectCredentialDumps } from './detectors/credentialDumpDetector.js';
export { detectExfiltration } from './detectors/exfiltrationDetector.js';
export { detectPatterns } from './detectors/patternDetector.js';
export { detectPII } from './detectors/piiDetector.js';
export { classifyTopics } from './detectors/topicClassifier.js';
