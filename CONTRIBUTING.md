# Contributing

Thanks for contributing to **NAXIUM Safeguard OSS**.

## Code of conduct (short)

- Be respectful and constructive.
- Do not submit real CSAM, live exploit payloads against third parties, or credentials.
- Test cases may use **synthetic** attack strings and placeholders only.

## License

By contributing, you agree that your contributions are licensed under the
**Apache License 2.0**. Copyright for the project is attributed to
[enderchefcoder](https://github.com/enderchefcoder) (see `LICENSE` and `NOTICE`).

New source files under `src/`, `test/`, and `scripts/` should include the
standard Apache-2.0 header. After adding files:

```bash
npm run headers
```

## Development setup

Requirements: **Node.js ≥ 18.17**, npm.

```bash
git clone https://github.com/enderchefcoder/naxium-safeguard-oss.git
cd naxium-safeguard-oss
npm install --legacy-peer-deps
npm test
npm run build
```

Useful scripts:

| Script | Purpose |
|--------|---------|
| `npm run typecheck` | TypeScript `--noEmit` |
| `npm run lint` | ESLint on `src` and `test` |
| `npm test` | Vitest unit suite |
| `npm run test:coverage` | Coverage report under `coverage/` |
| `npm run build` | Compile + copy `src/data` → `dist/data` |
| `npm run headers` | Ensure Apache-2.0 file headers |
| `npm run fixtures:awesome-jailbreak` | Regenerate Awesome-Jailbreak test fixtures |
| `npm run train:intent-model` | Retrain logistic intent model → `src/data/intentModel.json` |
| `npm run evaluate:guard` | Print benign/evasion confusion stats (requires build) |

## What to work on

Good contributions:

- Detector improvements that generalize (not single-prompt hardcodes)
- False-positive reductions with tests
- Docs clarity (especially `docs/LIMITATIONS.md`)
- CI, packaging, and TypeScript/API polish
- SSRF / secrets / tool-call hardening

Please avoid:

- Claiming the tool is unbypassable or “100% safe”
- Benchmaxing bibliography tests with paper-title regexes
- Committing one-off generator scripts that rewrite the whole lexicon unless discussed in an issue
- Disabling the CSAM hard-block

## Pull requests

1. Branch from `main` (or `master`).
2. Keep PRs focused and reviewable.
3. Include tests for behavior changes.
4. Ensure CI is green: quality (lint/typecheck/build) + tests on Node 18/20/22.
5. Update docs when you change public behavior or configuration.

PR description template (suggested):

```markdown
## Summary
-

## Test plan
- [ ] npm test
- [ ] npm run lint && npm run typecheck
- [ ] Manual check (if UI/CLI): …
```

## Reporting security issues

If you believe you found a vulnerability in the **sidecar, auth, or dependency surface**,
prefer a private report (GitHub Security Advisories if enabled) rather than a public issue
with a working exploit. Detection bypasses for heuristic layers are expected to some degree —
see `docs/LIMITATIONS.md` — and can usually be filed as normal enhancement issues.

## Architecture pointers

See `docs/ARCHITECTURE.md`, `AGENTS.md`, and `README.md`.
