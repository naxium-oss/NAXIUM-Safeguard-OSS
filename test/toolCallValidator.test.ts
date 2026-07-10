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
import { validateToolCall, isSSRF, parseIpv4 } from '../src/detectors/toolCallValidator.js';

describe('toolCallValidator SSRF', () => {
  it('blocks cloud metadata URL', () => {
    const signals = validateToolCall({
      toolName: 'fetch',
      args: { url: 'http://169.254.169.254/latest/meta-data/' },
    });
    expect(signals.some((s) => s.category === 'ssrf_attempt')).toBe(true);
  });

  it('blocks nested SSRF URLs', () => {
    const signals = validateToolCall({
      toolName: 'fetch',
      args: { nested: { url: 'http://127.0.0.1/admin' } },
    });
    expect(signals.some((s) => s.category === 'ssrf_attempt')).toBe(true);
  });

  it('blocks file:// scheme', () => {
    expect(isSSRF('file:///etc/passwd')).toBe(true);
  });

  it('blocks decimal and short-form IPv4', () => {
    expect(isSSRF('http://2130706433/')).toBe(true); // 127.0.0.1
    expect(isSSRF('http://127.1/')).toBe(true);
  });

  it('blocks whole-host hex and octal IPv4', () => {
    expect(isSSRF('http://0x7f000001/')).toBe(true);
    expect(parseIpv4('0x7f000001')).toBe(0x7f000001);
  });

  it('blocks benchmarking range 198.18/15', () => {
    expect(isSSRF('http://198.18.0.1/')).toBe(true);
  });

  it('blocks bare decimal and short-form hosts in tool args', () => {
    expect(
      validateToolCall({ toolName: 'fetch', args: { url: '2130706433' } }).some((s) => s.category === 'ssrf_attempt'),
    ).toBe(true);
    expect(
      validateToolCall({ toolName: 'fetch', args: { host: '127.1' } }).some((s) => s.category === 'ssrf_attempt'),
    ).toBe(true);
    expect(
      validateToolCall({ toolName: 'fetch', args: { url: '0x7f000001' } }).some((s) => s.category === 'ssrf_attempt'),
    ).toBe(true);
  });

  it('allows public https hosts (no ULA false positive)', () => {
    expect(isSSRF('https://facebook.com/api')).toBe(false);
    expect(isSSRF('https://example.com/path')).toBe(false);
  });

  it('blocks IPv6 ULA and link-local literals', () => {
    expect(isSSRF('http://[fc00::1]/')).toBe(true);
    expect(isSSRF('http://[fd12:3456::1]/')).toBe(true);
    expect(isSSRF('http://[fe80::1]/')).toBe(true);
  });

  it('blocks IPv4-mapped IPv6 localhost', () => {
    expect(isSSRF('http://[::ffff:127.0.0.1]/')).toBe(true);
  });

  it('blocks scheme-less private hosts', () => {
    expect(isSSRF('169.254.169.254/latest')).toBe(true);
    expect(isSSRF('10.0.0.5/secret')).toBe(true);
  });

  it('allows public https URLs', () => {
    expect(isSSRF('https://example.com/api')).toBe(false);
  });

  it('parseIpv4 handles dotted and decimal', () => {
    expect(parseIpv4('127.0.0.1')).toBe(0x7f000001);
    expect(parseIpv4('2130706433')).toBe(0x7f000001);
  });
});

describe('toolCallValidator other', () => {
  it('detects dangerous shell', () => {
    const signals = validateToolCall({ toolName: 'shell', args: { cmd: 'rm -rf /' } });
    expect(signals.some((s) => s.category === 'dangerous_shell_command')).toBe(true);
  });

  it('detects SQLi and path traversal', () => {
    const sqli = validateToolCall({ toolName: 'db', args: { q: '1 OR 1=1' } });
    expect(sqli.some((s) => s.category === 'sql_injection')).toBe(true);
    const path = validateToolCall({ toolName: 'read', args: { path: '../../etc/passwd' } });
    expect(path.some((s) => s.category === 'path_traversal')).toBe(true);
  });

  it('allows benign tool calls', () => {
    const signals = validateToolCall({
      toolName: 'search',
      args: { query: 'weather in paris' },
    });
    expect(signals).toHaveLength(0);
  });
});
