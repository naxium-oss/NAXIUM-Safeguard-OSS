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

/**
 * Build synthetic secret-shaped strings at runtime from parts so the full
 * token never appears contiguously in the git blob (avoids GitHub push
 * protection false positives on test fixtures).
 */
export function fx(...parts: string[]): string {
  return parts.join('');
}

const ALPHA = 'abcdefghijklmnopqrstuvwxyz';
const ALPHA_UP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';

export const FIXTURES = {
  openai: () => fx('sk-', ALPHA, DIGITS, 'ABCD'),
  openaiProject: () => fx('sk-proj-', ALPHA, DIGITS),
  anthropic: () => fx('sk-ant-api03-', ALPHA, DIGITS),
  stripeLive: () => fx('sk_', 'live_', ALPHA, '12'),
  stripeTest: () => fx('sk_', 'test_', ALPHA, '12'),
  npm: () => fx('npm_', ALPHA, '12', ALPHA_UP.slice(0, 6)),
  awsExample: () => fx('AKIA', 'IOSFODNN7EXAMPLE'),
  githubPatClassic: () => fx('ghp_', ALPHA, DIGITS),
  githubPatFine: () => fx('github_pat_11', ALPHA_UP.slice(0, 22), '_', ALPHA, DIGITS),
  huggingFace: () => fx('hf_', ALPHA, '12'),
  slackBot: () => fx('xox', 'b-', '123456789012-', ALPHA.slice(0, 24)),
  slackWebhook: () =>
    fx('https://hooks.', 'slack.com/services/', 'T00000000/', 'B00000000/', 'X'.repeat(24)),
  googleApi: () => fx('AIza', 'SyA-', ALPHA.slice(0, 20), DIGITS, '1'),
  sendGrid: () => fx('SG.', ALPHA.slice(0, 16), '.', ALPHA_UP, ALPHA.slice(0, 4)),
  mailgun: () => fx('key-', '0123456789abcdef', '0123456789abcdef'),
  shopify: () => fx('shpat_', '0123456789abcdef', '0123456789abcdef'),
  digitalOcean: () => fx('dop_v1_', 'a'.repeat(64)),
  pypi: () => fx('pypi-', 'AgEIcHlwaS5vcmcCJD', ALPHA.slice(0, 20)),
  postgresUri: () => fx('postgresql://user:', 's3cretPass', '@db.example.com:5432/app'),
  mongoUri: () => fx('mongodb+srv://user:', 's3cret', '@cluster0.example.mongodb.net/db'),
  bearerJwt: () => fx('Authorization: Bearer ', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.', 'aaa.', 'bbb'),
  rsaPrivateKey: () =>
    fx('-----BEGIN ', 'RSA PRIVATE KEY-----\n', 'MIIEowIBAAKCAQEA0Z3VS5J\n', '-----END RSA PRIVATE KEY-----'),
  discordWebhook: () =>
    fx('https://discord.com/api/webhooks/', '123456789012345678/', ALPHA, ALPHA_UP.slice(0, 14)),
  twilioSid: () => fx('AC', 'a'.repeat(32)),
  passwordAssign: () => fx('password=', 'SuperSecret123!'),
} as const;
