# Security Levels

| Level | Block Threshold | Flag Threshold | Obfuscation Decode | Semantic Similarity | Statistical Intent | Multilingual Intent | Session Tracking | Strict PII | Rate Limit/min | Lockout after |
|-------|------------------|-----------------|----------------------|------------------------|--------------------|---------------------|------------------|------------|------------------|----------------|
| 0     | 0.90             | 0.60            | off                  | off                    | off                | off                 | off              | off        | 300              | 10 violations  |
| 2     | 0.77             | 0.50            | on                   | off                    | off                | on                  | off              | off        | 242              | 8              |
| 4     | 0.64             | 0.41            | on                   | on                     | on (from 3)        | on                  | on               | off        | 184              | 7              |
| 6     | 0.51             | 0.31            | on                   | on                     | on                 | on                  | on               | on         | 126              | 5              |
| 8     | 0.38             | 0.22            | on                   | on                     | on                 | on                  | on               | on         | 68               | 3              |
| 10    | 0.25             | 0.12            | on                   | on                     | on                 | on                  | on               | on         | 10               | 2              |

Stance dampening fully trusts defensive/educational framing through level 6, then tapers. Session risk weight scales with level (0 at level 0).

Values are computed deterministically by `buildLevelConfig()` — see
`src/config/securityLevels.ts` for the exact formula. Tune it for your app.
