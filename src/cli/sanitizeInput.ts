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
/* eslint-disable no-control-regex -- intentionally matching terminal control / CSI bytes */
/**
 * Strip terminal mouse / CSI / OSC junk that Windows terminals often dump
 * into stdin when the mouse moves over the window.
 *
 * IMPORTANT: do NOT trim here. Trimming on every keystroke makes spaces
 * impossible to type (trailing space is wiped as soon as you press Space).
 * Callers should trim only on submit.
 */
export function sanitizeTerminalInput(raw: string): string {
  let s = raw;
  // OSC sequences: ESC ] ... BEL or ST
  s = s.replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g, '');
  // CSI sequences: ESC [ ... final byte
  s = s.replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '');
  // Bare CSI often seen as "<35;61;41M" style mouse reports without ESC
  s = s.replace(/\[<?\d+(?:;\d+)*[A-Za-z]/g, '');
  // Other ESC-prefixed controls
  s = s.replace(/\u001b./g, '');
  // Non-printable controls except tab/newline
  s = s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  return s;
}

export function isGarbageTerminalInput(raw: string): boolean {
  const cleaned = sanitizeTerminalInput(raw).trim();
  if (!cleaned) return true;
  // Mostly punctuation / digits from mouse reports
  const letters = cleaned.replace(/[^a-zA-Z]/g, '');
  return letters.length < 2 && cleaned.length > 8;
}
