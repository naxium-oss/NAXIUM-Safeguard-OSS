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
import request from 'supertest';
import { createApp } from '../src/server/createApp.js';
import { NaxiumSafeguard } from '../src/core/NaxiumSafeguard.js';

describe('X-Forwarded-For / trust proxy', () => {
  it('ignores spoofed XFF when trustProxy is off', async () => {
    const safeguard = new NaxiumSafeguard({
      securityLevel: 10,
      logging: { enabled: false, logSafeRequests: false },
    });
    const { app } = createApp({ securityLevel: 10, safeguard, trustProxy: false });

    for (let i = 0; i < 10; i++) {
      await request(app)
        .post('/v1/guard/input')
        .set('X-Forwarded-For', `203.0.113.${i}`)
        .send({ text: 'hello' });
    }

    const limited = await request(app)
      .post('/v1/guard/input')
      .set('X-Forwarded-For', '203.0.113.99')
      .send({ text: 'hello' });

    expect(limited.body.blockedCategories).toContain('rate_limit_exceeded');
  });

  it('uses XFF via req.ip when trustProxy is on', async () => {
    const safeguard = new NaxiumSafeguard({
      securityLevel: 10,
      logging: { enabled: false, logSafeRequests: false },
    });
    const { app } = createApp({ securityLevel: 10, safeguard, trustProxy: true });

    for (let i = 0; i < 10; i++) {
      await request(app)
        .post('/v1/guard/input')
        .set('X-Forwarded-For', '198.51.100.10')
        .send({ text: 'hello' });
    }

    const limitedSame = await request(app)
      .post('/v1/guard/input')
      .set('X-Forwarded-For', '198.51.100.10')
      .send({ text: 'hello' });
    expect(limitedSame.body.blockedCategories).toContain('rate_limit_exceeded');

    const otherClient = await request(app)
      .post('/v1/guard/input')
      .set('X-Forwarded-For', '198.51.100.20')
      .send({ text: 'hello' });
    expect(otherClient.body.blockedCategories ?? []).not.toContain('rate_limit_exceeded');
  });
});

describe('payload limits', () => {
  it('rejects oversized bodies', async () => {
    const { app } = createApp({ securityLevel: 6 });
    const res = await request(app)
      .post('/v1/guard/input')
      .send({ text: 'a'.repeat(70_000) });
    // Express body parser rejects before Zod when over jsonLimit
    expect([400, 413]).toContain(res.status);
    expect(['validation_error', 'payload_too_large']).toContain(res.body.error);
  });

  it('rejects via zod when under body limit but over text max', async () => {
    const { app } = createApp({ securityLevel: 6, jsonLimit: '200kb' });
    const res = await request(app)
      .post('/v1/guard/input')
      .send({ text: 'a'.repeat(70_000) });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('validation_error');
  });
});
