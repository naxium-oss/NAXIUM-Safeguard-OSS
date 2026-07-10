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
import { z } from 'zod';

export const guardContextSchema = z
  .object({
    userId: z.string().max(256).optional(),
    sessionId: z.string().max(256).optional(),
    ip: z.string().max(128).optional(),
    channel: z.enum(['input', 'output', 'tool']).optional(),
    metadata: z.record(z.unknown()).optional(),
  })
  .strict()
  .optional()
  .default({});

export const guardTextBodySchema = z
  .object({
    text: z.string().max(65_536),
    context: guardContextSchema,
  })
  .strict();

export const guardToolBodySchema = z
  .object({
    toolName: z.string().min(1).max(256),
    args: z.record(z.unknown()),
    context: guardContextSchema,
  })
  .strict();

export const sessionResetBodySchema = z
  .object({
    sessionKey: z.string().max(256).optional(),
  })
  .strict()
  .optional()
  .default({});
