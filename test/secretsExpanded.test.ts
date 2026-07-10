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
import { scanForSecrets } from '../src/detectors/secretsScanner.js';
import { FIXTURES } from './helpers/secretFixtures.js';

const CASES: { label: string; sample: () => string }[] = [
  { label: 'OpenAI', sample: FIXTURES.openai },
  { label: 'OpenAI project', sample: FIXTURES.openaiProject },
  { label: 'Anthropic', sample: FIXTURES.anthropic },
  { label: 'Stripe live', sample: FIXTURES.stripeLive },
  { label: 'Stripe test', sample: FIXTURES.stripeTest },
  { label: 'npm', sample: FIXTURES.npm },
  { label: 'AWS', sample: FIXTURES.awsExample },
  { label: 'GitHub', sample: FIXTURES.githubPatClassic },
  { label: 'GitHub PAT', sample: FIXTURES.githubPatFine },
  { label: 'HuggingFace', sample: FIXTURES.huggingFace },
  { label: 'Slack', sample: FIXTURES.slackBot },
  { label: 'Slack webhook', sample: FIXTURES.slackWebhook },
  { label: 'Google', sample: FIXTURES.googleApi },
  { label: 'SendGrid', sample: FIXTURES.sendGrid },
  { label: 'Mailgun', sample: FIXTURES.mailgun },
  { label: 'Shopify', sample: FIXTURES.shopify },
  { label: 'DigitalOcean', sample: FIXTURES.digitalOcean },
  { label: 'PyPI', sample: FIXTURES.pypi },
  { label: 'Postgres URI', sample: FIXTURES.postgresUri },
  { label: 'Mongo URI', sample: FIXTURES.mongoUri },
  { label: 'Bearer', sample: FIXTURES.bearerJwt },
  { label: 'Private key', sample: FIXTURES.rsaPrivateKey },
  { label: 'Discord webhook', sample: FIXTURES.discordWebhook },
  { label: 'Twilio SID', sample: FIXTURES.twilioSid },
];

describe('secretsScanner expanded corpus', () => {
  it.each(CASES)('detects $label', ({ sample }) => {
    const signals = scanForSecrets(sample());
    expect(signals.some((s) => s.category.startsWith('secret_leak'))).toBe(true);
  });

  it('redacts matched secrets', () => {
    const signals = scanForSecrets(FIXTURES.openai());
    expect(signals[0]?.matched[0]).toMatch(/\.\.\./);
  });
});
