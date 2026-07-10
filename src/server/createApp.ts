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
import express, { type Express, type Request, type Response, type NextFunction } from 'express';
import { NaxiumSafeguard } from '../core/NaxiumSafeguard.js';
import { buildRoutes } from './routes.js';
import { timingSafeEqualString } from '../utils/timingSafeEqual.js';
import { parseSecurityLevel } from '../utils/parseSecurityLevel.js';
import { deriveProtectionKey } from '../utils/deriveProtectionKey.js';
import type { SecurityLevel } from '../types.js';

export interface CreateAppOptions {
  apiKey?: string | undefined;
  securityLevel?: SecurityLevel;
  requireApiKey?: boolean;
  safeguard?: NaxiumSafeguard;
  trustProxy?: boolean;
  /** Max JSON body size (default 64kb — keeps detector CPU bounded). */
  jsonLimit?: string;
}

export { deriveProtectionKey };

export function createApp(options: CreateAppOptions = {}): {
  app: Express;
  safeguard: NaxiumSafeguard;
} {
  const apiKey = options.apiKey;
  const requireApiKey = options.requireApiKey ?? false;
  const securityLevel = parseSecurityLevel(options.securityLevel ?? 6);
  const safeguard = options.safeguard ?? new NaxiumSafeguard({ securityLevel });

  if (requireApiKey && (!apiKey || apiKey.length < 8)) {
    throw new Error('NAXIUM_API_KEY is required (min 8 chars) when requireApiKey is enabled');
  }

  const app = express();
  if (options.trustProxy) app.set('trust proxy', 1);

  app.disable('x-powered-by');
  app.use(express.json({ limit: options.jsonLimit ?? '64kb' }));

  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  // Liveness probe outside /v1 so auth bypass is unambiguous
  app.get('/health', (_req, res) => res.json({ status: 'ok' }));

  if (apiKey) {
    app.use('/v1', (req, res, next) => {
      if (req.path === '/health') return next();
      const key = req.header('x-naxium-api-key') ?? '';
      if (!timingSafeEqualString(key, apiKey)) {
        return res.status(401).json({ error: 'unauthorized' });
      }
      next();
    });
  } else if (requireApiKey) {
    throw new Error('API key required but not provided');
  }

  app.use('/v1', buildRoutes(safeguard, { deriveProtectionKey }));

  app.use((err: unknown, _req: Request, res: Response, next: NextFunction) => {
    if (res.headersSent) return next(err);
    const anyErr = err as { type?: string; status?: number; statusCode?: number; message?: string };
    if (anyErr?.type === 'entity.too.large' || anyErr?.status === 413 || anyErr?.statusCode === 413) {
      return res.status(413).json({ error: 'payload_too_large' });
    }
    console.error('[naxium] unhandled error', err instanceof Error ? err.message : err);
    res.status(500).json({ error: 'internal_error' });
  });

  return { app, safeguard };
}
