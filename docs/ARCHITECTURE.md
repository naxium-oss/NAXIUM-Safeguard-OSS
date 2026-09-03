# Architecture

NAXIUM Safeguard OSS is a **local, multi-layer heuristic** pipeline. Every detector
runs in-process; there is no required network call for scoring.

```
┌────────────────┐   guardInput / guardOutput / guardToolCall   ┌──────────────────┐
│ Caller (app /  │ ────────────────────────────────────────────▶│  NaxiumSafeguard │
│ CLI / HTTP)    │                                              └────────┬─────────┘
└────────────────┘                                                       │
                    buildVariants() — canonical + evasive forms            │
                                         │                               │
         ┌───────────────────────────────┼───────────────────────────────┤
         ▼               ▼               ▼               ▼               ▼
    patterns        obfuscation      intent /        topics /        secrets /
    + fuzzy         variant rescan   disguise /      high-signal     PII / exfil
    + n-gram        + payload      authority /     tokens
    + multilingual    split          slot-fill /
    + statistical                  verb-chain /
    + config DSL                   code-smuggle /
    + prompt markers               url-threat /
                                   repetition /
                                   destructive shell
                                         │
                    analyzeStance() — dampen dual-use evidence when benign
                                         │
                                         ▼
                                  riskEngine.assessRisk()
                          primary vs corroborating · session carry-over
                                   allow | flag | block | lockout
                                         │
                                  sanitizer (wipe + alert)
                                         │
                                         ▼
                              GuardResult (+ stance on input)
```

## Channels

| Channel | Typical detectors |
|---------|-------------------|
| **input** | Full stack: variant pipeline, jailbreak heuristics, topics, secrets, PII, destructive shell, contrastive TF-IDF, statistical intent, multilingual cues, session tracking |
| **output** | Secrets, credential dumps, exfil, PII, topics, output-compliance (prompt leaks / jailbreak agreement), limited jailbreak categories |
| **tool** | SSRF blocklist / private IP checks, dangerous shell, SQLi / path traversal |

## Risk engine

- Signals are grouped per detector+category; repeat hits from variant rescans do not stack naively.
- **Primary** evidence can block; **corroborating** evidence (n-gram overlap, weak similarity) supports but cannot hard-block alone.
- **Request stance** (operational vs defensive/informational/creative) discounts dual-use vocabulary when the ask is clearly protective or educational.
- **Session risk** carries decaying escalation scores for multi-turn jailbreak pressure (crescendo attacks).
- Security level (0–10) sets block/flag thresholds and which heavy detectors are enabled.
- Category **`csam`** hard-blocks at every level (documented exception).

## Data

Committed JSON under `src/data/` (copied to `dist/data` on build):

- `jailbreakPatterns.json`, `topicLexicons.json`, `knownAttackCorpus.json`, `benignCorpus.json`
- `disguisePhrases.json`, `highSignalTokens.json`, `ngramRiskBank.json`
- `lexicalBaseline.json`, `stanceCues.json`, `multilingualLexicon.json`
- `intentModel.json` (logistic weights — retrain with `npm run train:intent-model`)
- `secretsPatterns.json`, `ssrfBlocklist.json`

## Surfaces

- **Library:** `NaxiumSafeguard` from `naxium-safeguard-oss`
- **CLI / TUI:** `naxiguard`
- **HTTP sidecar:** Express app in `src/server/`
- **Middleware:** `createExpressMiddleware`

For honesty about gaps, see `docs/LIMITATIONS.md`. For level math, see `docs/SECURITY_LEVELS.md`.
