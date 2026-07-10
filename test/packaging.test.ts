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
import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';

describe('packaging and license', () => {
  it('declares Apache-2.0 with enderchefcoder copyright', () => {
    const license = readFileSync('LICENSE', 'utf8');
    expect(license).toMatch(/Apache License/);
    expect(license).toMatch(/Version 2\.0/);

    const notice = readFileSync('NOTICE', 'utf8');
    expect(notice).toMatch(/enderchefcoder/);
    expect(notice).toMatch(/Apache License, Version 2\.0/);

    const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as {
      license: string;
      author: { name: string };
    };
    expect(pkg.license).toBe('Apache-2.0');
    expect(pkg.author.name).toBe('enderchefcoder');
  });

  it('ships NOTICE with the package files list', () => {
    const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as { files: string[] };
    expect(pkg.files).toContain('LICENSE');
    expect(pkg.files).toContain('NOTICE');
    expect(pkg.files).toContain('docs');
  });
});
