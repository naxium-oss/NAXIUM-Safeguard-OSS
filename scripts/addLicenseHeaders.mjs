/**
 * Prepend Apache-2.0 + enderchefcoder copyright headers to source files.
 * Idempotent: skips files that already contain SPDX-License-Identifier: Apache-2.0
 *
 * Usage: node scripts/addLicenseHeaders.mjs
 */
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';

const ROOT = process.cwd();
const DIRS = ['src', 'test', 'scripts'];
const EXTS = new Set(['.ts', '.tsx', '.js', '.mjs', '.cjs']);

const BLOCK = `/**
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
`;

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (name === 'node_modules' || name === 'dist' || name === 'fixtures') continue;
      walk(p, out);
    } else if (EXTS.has(extname(name))) {
      out.push(p);
    }
  }
  return out;
}

let updated = 0;
let skipped = 0;

for (const dir of DIRS) {
  const abs = join(ROOT, dir);
  try {
    statSync(abs);
  } catch {
    continue;
  }
  for (const file of walk(abs)) {
    let src = readFileSync(file, 'utf8');
    if (src.includes('SPDX-License-Identifier: Apache-2.0')) {
      skipped += 1;
      continue;
    }
    // Preserve shebang
    if (src.startsWith('#!')) {
      const nl = src.indexOf('\n');
      const shebang = src.slice(0, nl + 1);
      const rest = src.slice(nl + 1);
      src = shebang + BLOCK + rest;
    } else {
      src = BLOCK + src;
    }
    writeFileSync(file, src);
    updated += 1;
  }
}

console.log(JSON.stringify({ updated, skipped }, null, 2));
