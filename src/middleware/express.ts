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
import type { Request, Response, NextFunction } from 'express';
import type { NaxiumSafeguard } from '../core/NaxiumSafeguard.js';
import type { GuardContext } from '../types.js';
import { deriveProtectionKey } from '../utils/deriveProtectionKey.js';

export interface MiddlewareOptions {
  channel: 'input' | 'output';
  extractText: (req: Request) => string | undefined | null;
  extractContext?: (req: Request) => Partial<GuardContext>;
  /** When true, expose riskScore/categories to the client. Default false. */
  exposeDetails?: boolean;
}

export function createExpressMiddleware(safeguard: NaxiumSafeguard, options: MiddlewareOptions) {
  const exposeDetails = options.exposeDetails ?? false;

  return (req: Request, res: Response, next: NextFunction) => {
    const text = options.extractText(req);
    if (typeof text !== 'string') {
      return res.status(400).json({ error: 'text (string) is required' });
    }

    const protectionKey = deriveProtectionKey(req);
    const extra = options.extractContext?.(req) ?? {};
    const context: GuardContext = {
      ...extra,
      protectionKey,
      ip: protectionKey,
    };

    const result =
      options.channel === 'input' ? safeguard.guardInput(text, context) : safeguard.guardOutput(text, context);

    (req as Request & { naxium?: unknown }).naxium = result;

    if (!result.safe) {
      const body: Record<string, unknown> = {
        error: result.alertMessage,
        action: result.action,
      };
      if (exposeDetails) {
        body.riskScore = result.riskScore;
        body.blockedCategories = result.blockedCategories;
      }
      return res.status(result.action === 'lockout' ? 429 : 403).json(body);
    }

    next();
  };
}
