#!/usr/bin/env node
/**
 * Copyright 2026 enderchefcoder
 * SPDX-License-Identifier: Apache-2.0
 *
 * Maintainer harness: print per-level confusion stats for curated fixtures.
 *
 * Usage: node scripts/evaluateGuard.mjs [level]
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const level = Number(process.argv[2] ?? 8);

const { NaxiumSafeguard } = await import(join(root, 'dist/core/NaxiumSafeguard.js')).catch(() =>
  import(join(root, 'src/core/NaxiumSafeguard.ts')),
);

const benign = JSON.parse(readFileSync(join(root, 'test/fixtures/benignPrompts.json'), 'utf8'));
const evasions = JSON.parse(readFileSync(join(root, 'test/fixtures/evasionAttacks.json'), 'utf8'));

const guard = new NaxiumSafeguard({
  securityLevel: level,
  logging: { enabled: false, logSafeRequests: false },
});

let fp = 0;
let fn = 0;
let flags = 0;

for (const prompt of benign) {
  const result = guard.guardInput(prompt, { protectionKey: `b-${prompt.length}` });
  if (!result.safe && result.action === 'block') fp += 1;
  if (result.action === 'flag') flags += 1;
}

for (const attack of evasions) {
  const result = guard.guardInput(attack.prompt, { protectionKey: attack.id });
  if (result.safe) fn += 1;
}

console.log(`Level ${level} evaluation`);
console.log(`  Benign prompts: ${benign.length}`);
console.log(`  False blocks:   ${fp}`);
console.log(`  Benign flags:   ${flags}`);
console.log(`  Evasion attacks: ${evasions.length}`);
console.log(`  Misses:         ${fn}`);
console.log(`  Catch rate:     ${(((evasions.length - fn) / evasions.length) * 100).toFixed(1)}%`);

if (fp > 0 || fn / evasions.length > 0.05) process.exitCode = 1;
