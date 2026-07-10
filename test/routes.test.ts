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

describe('HTTP routes', () => {
  it('serves /health without auth', async () => {
    const { app } = createApp({ apiKey: 'test-secret-key', securityLevel: 6 });
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });

  it('serves /v1/health without auth when key configured', async () => {
    const { app } = createApp({ apiKey: 'test-secret-key', securityLevel: 6 });
    const res = await request(app).get('/v1/health');
    expect(res.status).toBe(200);
  });

  it('rejects missing API key', async () => {
    const { app } = createApp({ apiKey: 'test-secret-key', securityLevel: 6 });
    const res = await request(app).post('/v1/guard/input').send({ text: 'hi' });
    expect(res.status).toBe(401);
  });

  it('accepts correct API key', async () => {
    const { app } = createApp({ apiKey: 'test-secret-key', securityLevel: 6 });
    const res = await request(app)
      .post('/v1/guard/input')
      .set('x-naxium-api-key', 'test-secret-key')
      .send({ text: 'What is the weather?' });
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('safe');
    expect(res.body).toHaveProperty('action');
  });

  it('validates body with zod', async () => {
    const { app } = createApp({ securityLevel: 6 });
    const res = await request(app).post('/v1/guard/input').send({ text: 123 });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('validation_error');
  });

  it('rejects array args for tool-call', async () => {
    const { app } = createApp({ securityLevel: 6 });
    const res = await request(app)
      .post('/v1/guard/tool-call')
      .send({ toolName: 'x', args: [1, 2] });
    expect(res.status).toBe(400);
  });

  it('guards tool-call SSRF', async () => {
    const { app } = createApp({ securityLevel: 6 });
    const res = await request(app)
      .post('/v1/guard/tool-call')
      .send({ toolName: 'fetch', args: { url: 'http://127.0.0.1/' } });
    expect(res.status).toBe(200);
    expect(res.body.safe).toBe(false);
  });

  it('session reset only clears caller protection key', async () => {
    const safeguard = new NaxiumSafeguard({
      securityLevel: 10,
      logging: { enabled: false, logSafeRequests: false },
    });
    const { app } = createApp({ securityLevel: 10, safeguard });

    for (let i = 0; i < 10; i++) {
      await request(app).post('/v1/guard/input').send({ text: 'hello', context: { sessionId: `s${i}` } });
    }
    const limited = await request(app).post('/v1/guard/input').send({ text: 'hello' });
    expect(limited.body.blockedCategories).toContain('rate_limit_exceeded');

    await request(app).post('/v1/session/reset').send({ sessionKey: 'attacker-guess' });
    const after = await request(app).post('/v1/guard/input').send({ text: 'hello again' });
    // Reset should have cleared the caller's pk-based bucket
    expect(after.body.blockedCategories ?? []).not.toContain('rate_limit_exceeded');
  });

  it('ignores client sessionId rotation for rate limits', async () => {
    const { app } = createApp({ securityLevel: 10 });
    for (let i = 0; i < 10; i++) {
      await request(app)
        .post('/v1/guard/input')
        .send({ text: 'hello', context: { sessionId: `unique-${i}` } });
    }
    const limited = await request(app)
      .post('/v1/guard/input')
      .send({ text: 'hello', context: { sessionId: 'unique-new' } });
    expect(limited.body.blockedCategories).toContain('rate_limit_exceeded');
  });
});
