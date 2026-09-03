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
import { buildLevelConfig } from './securityLevels.js';
import type { SecurityLevel } from '../types.js';

export interface NaxiumConfig {
  securityLevel: SecurityLevel;
  appName: string;
  alertMessage: {
    input: string;
    output: string;
    toolCall: string;
    lockout: string;
  };
  wipeOnBlock: boolean;
  logging: {
    enabled: boolean;
    logPath?: string;
    logSafeRequests: boolean;
  };
  /** Per-category risk multipliers (1 = default). */
  categoryWeights?: Record<string, number>;
}

export const DEFAULT_CONFIG: NaxiumConfig = {
  securityLevel: 6,
  appName: 'naxium-safeguard',
  alertMessage: {
    input:
      'Your message was blocked by NAXIUM Safeguard because it matched patterns associated with unsafe or policy-violating content.',
    output:
      'The generated response was blocked by NAXIUM Safeguard before delivery due to policy-violating content.',
    toolCall:
      'The requested tool action was blocked by NAXIUM Safeguard due to a potential security risk.',
    lockout:
      'Too many unsafe attempts were detected. This session has been temporarily locked out.',
  },
  wipeOnBlock: true,
  logging: {
    // Default off to avoid leaking prompt previews to stdout in library embeds.
    // Sidecar / ops can enable explicitly.
    enabled: false,
    logSafeRequests: false,
  },
};

export function resolveLevelConfig(cfg: NaxiumConfig) {
  return buildLevelConfig(cfg.securityLevel);
}
