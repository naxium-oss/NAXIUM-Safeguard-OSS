# Architecture

NAXIUM Safeguard OSS is a **local, multi-layer heuristic** pipeline. Every detector
runs in-process; there is no required network call for scoring.

```
┌────────────────┐   guardInput / guardOutput / guardToolCall   ┌──────────────────┐
│ Caller (app /  │ ────────────────────────────────────────────▶│  NaxiumSafeguard │
│ CLI / HTTP)    │                                              └────────┬─────────┘
└────────────────┘                                                       │
                         normalize (unicode / size caps)                 │
                                         │                               │
         ┌───────────────────────────────┼───────────────────────────────┤
         ▼               ▼               ▼               ▼               ▼
    patterns        obfuscation      intent /        topics /        secrets /
    + fuzzy         decode+recheck   disguise /      high-signal     PII / exfil
    + n-gram                         authority /     tokens
                                     slot-fill /
                                     verb-chain /
                                     code-smuggle /
                                     url-threat /
                                     repetition /
                                     destructive shell
                                         │
                                         ▼
                                  riskEngine.assessRisk()
                                   allow | flag | block | lockout
                                         │
                                  sanitizer (wipe + alert)
                                         │
                                         ▼
                                    GuardResult
```

## Channels

| Channel | Typical detectors |
|---------|-------------------|
| **input** | Full stack (jailbreak, topics, secrets, PII, destructive shell, heuristics, semantic TF-IDF, …) |
| **output** | Secrets, credential dumps, exfil, PII, topics; limited jailbreak categories |
| **tool** | SSRF blocklist / private IP checks, dangerous shell, SQLi / path traversal |

## Risk engine

- Signals are scored with diminishing returns (dominant signal + corroboration).
- Security level (0–10) sets block/flag thresholds and which heavy detectors are enabled.
- Category **`csam`** hard-blocks at every level (documented exception).

## Data

Committed JSON under `src/data/` (copied to `dist/data` on build):

- `jailbreakPatterns.json`, `topicLexicons.json`, `knownAttackCorpus.json`
- `disguisePhrases.json`, `highSignalTokens.json`, `ngramRiskBank.json`
- `secretsPatterns.json`, `ssrfBlocklist.json`

## Surfaces

- **Library:** `NaxiumSafeguard` from `naxium-safeguard-oss`
- **CLI / TUI:** `naxiguard`
- **HTTP sidecar:** Express app in `src/server/`
- **Middleware:** `createExpressMiddleware`

For honesty about gaps, see `docs/LIMITATIONS.md`. For level math, see `docs/SECURITY_LEVELS.md`.
