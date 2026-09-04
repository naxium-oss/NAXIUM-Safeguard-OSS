# AGENTS.md

Guidance for coding agents and automated contributors working in this repository.

## Project identity

- **Package:** `naxium-safeguard-oss`
- **CLI:** `naxiguard`
- **License:** Apache-2.0 — Copyright 2026 [enderchefcoder](https://github.com/enderchefcoder)
- **Purpose:** Local-first **heuristic** safeguard for LLM inputs, outputs, and tool calls. Not a neural safety model and not “unbypassable.”

## Hard rules

1. **Be honest in docs and marketing language.** Do not claim 100% jailbreak-proof, unbypassable, or guaranteed detection.
2. **Do not benchmax bibliography tests.** Awesome-Jailbreak fixtures use technique-family prompts. Never add paper-title regexes to pass those tests.
3. **CSAM hard-block stays non-negotiable** in `riskEngine` regardless of security level.
4. **No inline imports** — keep imports at the top of modules.
5. **Exhaustive switches** on unions/enums — use a `never` default.
6. **Do not commit secrets.** `.env` is gitignored; use `.env.example` for templates.
7. **Prefer fixing detectors generally** when a family of attacks slips through — not one-off strings for a single demo prompt.
8. **TUI input:** never `.trim()` on every keystroke (breaks spaces). Trim on submit only.
9. **License headers:** source under `src/`, `test/`, and `scripts/` should carry SPDX `Apache-2.0` and copyright `enderchefcoder`. Run `npm run headers` after adding files.
10. **Intent model:** after editing `benignCorpus.json` or `knownAttackCorpus.json`, run `npm run train:intent-model` and commit the updated `src/data/intentModel.json`.

## Layout

| Path | Role |
|------|------|
| `src/core/` | `NaxiumSafeguard`, risk engine, sanitizer |
| `src/detectors/` | Individual detection layers |
| `src/data/` | Lexicons, patterns, corpora (committed JSON) |
| `src/cli/` | CLI + Ink TUI |
| `src/server/` | HTTP sidecar |
| `src/middleware/` | Express middleware |
| `test/` | Vitest suite |
| `test/fixtures/` | Committed fixtures (e.g. Awesome-Jailbreak) |
| `docs/` | Architecture, security, limitations, levels |
| `scripts/` | Maintainer utilities (`copy-assets`, `headers`, fixture regen, intent trainer) |

## Commands

```bash
npm install --legacy-peer-deps
npm run typecheck
npm run lint
npm test
npm run test:coverage
npm run build
npm run headers
npm run fixtures:awesome-jailbreak   # regenerate bibliography fixtures only
npm run train:intent-model           # retrain logistic intent weights after corpus edits
npm run evaluate:guard               # benign/evasion confusion stats (requires build)
```

## Changing detection data

- Edit JSON under `src/data/` directly (or with a one-off local script you **do not** commit unless it is a documented maintainer tool).
- After data changes, run `npm test` and `npm run build` (assets are copied to `dist/data`).
- Keep false-positive discipline: short benign prompts (`hello`, `secure my site`, `clean`) should still allow at default CLI level unless they are truly high-signal.

## Testing expectations

- Default CLI level (`DEFAULT_CLI_LEVEL`) must continue to block classic demos (`test/smokeDefaultLevel.test.ts`).
- Novel / paraphrased attacks: prefer `intentHeuristic`, disguise, fuzzy, and semantic layers over title memorization.
- Red-team tests document floors and honesty — do not weaken them to hide gaps.

## PR checklist for agents

- [ ] `npm run typecheck && npm run lint && npm test && npm run build`
- [ ] Docs updated if behavior or public API changed
- [ ] No temporary `generateInsane*` / scratch scripts left in `scripts/`
- [ ] License headers present on new source files
- [ ] Limitations remain accurate if detection claims changed
