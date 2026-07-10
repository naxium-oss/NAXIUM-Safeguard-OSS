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
import { Router, type Request } from 'express';
import type { NaxiumSafeguard } from '../core/NaxiumSafeguard.js';
import { guardTextBodySchema, guardToolBodySchema, sessionResetBodySchema } from './schemas.js';
import { ZodError } from 'zod';

export interface RouteOptions {
  deriveProtectionKey: (req: Request) => string;
}

function zodError(res: import('express').Response, err: ZodError) {
  return res.status(400).json({
    error: 'validation_error',
    details: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
  });
}

export function buildRoutes(safeguard: NaxiumSafeguard, options: RouteOptions): Router {
  const router = Router();

  router.get('/health', (_req, res) => res.json({ status: 'ok' }));

  router.post('/guard/input', (req, res) => {
    try {
      const body = guardTextBodySchema.parse(req.body ?? {});
      const protectionKey = options.deriveProtectionKey(req);
      const context = { ...body.context, protectionKey, ip: protectionKey };
      res.json(safeguard.guardInput(body.text, context));
    } catch (err) {
      if (err instanceof ZodError) return zodError(res, err);
      throw err;
    }
  });

  router.post('/guard/output', (req, res) => {
    try {
      const body = guardTextBodySchema.parse(req.body ?? {});
      const protectionKey = options.deriveProtectionKey(req);
      const context = { ...body.context, protectionKey, ip: protectionKey };
      res.json(safeguard.guardOutput(body.text, context));
    } catch (err) {
      if (err instanceof ZodError) return zodError(res, err);
      throw err;
    }
  });

  router.post('/guard/tool-call', (req, res) => {
    try {
      const body = guardToolBodySchema.parse(req.body ?? {});
      const protectionKey = options.deriveProtectionKey(req);
      const context = { ...body.context, protectionKey, ip: protectionKey };
      res.json(safeguard.guardToolCall({ toolName: body.toolName, args: body.args }, context));
    } catch (err) {
      if (err instanceof ZodError) return zodError(res, err);
      throw err;
    }
  });

  /**
   * Resets rate-limit / lockout for the calling client only
   * (derived from connection identity). Body sessionKey is ignored for
   * protection state to prevent cross-tenant reset attacks.
   */
  router.post('/session/reset', (req, res) => {
    try {
      sessionResetBodySchema.parse(req.body ?? {});
      const protectionKey = options.deriveProtectionKey(req);
      safeguard.resetSession(protectionKey);
      res.json({ ok: true });
    } catch (err) {
      if (err instanceof ZodError) return zodError(res, err);
      throw err;
    }
  });

  return router;
}
