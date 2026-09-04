# Testing

## Running tests

```bash
npm test                 # full Vitest suite
npm run test:watch       # watch mode
npm run test:coverage    # coverage under coverage/ (thresholds in vitest.config.ts)
npm run ci               # typecheck + lint + test + build
npm run train:intent-model   # retrain logistic intent weights after corpus edits
npm run evaluate:guard       # print benign/evasion confusion stats (requires build)
```

## What the suite covers

| Area | Examples |
|------|----------|
| Core API | `NaxiumSafeguard.test.ts`, `riskEngine.test.ts` |
| Detectors | `detectorLayers.test.ts`, `disguiseAndExpansion.test.ts`, `knownAttacks.test.ts` |
| Defaults / smoke | `smokeDefaultLevel.test.ts` — CLI default level must block classic demos |
| Accuracy floors | `guardAccuracy.test.ts` — benign prompts must allow; evasion fixture ≥95% catch @ level 8 |
| Overhaul layers | `guardOverhaulLayers.test.ts` — stance, variants, session, new detectors |
| Novel paraphrases | `novelJailbreakIntent.test.ts`, `redteam.test.ts` |
| Bibliography floor | `awesomeJailbreakPapers.test.ts` — technique-family fixtures, **no title benchmax** |
| HTTP / middleware | `routes.test.ts`, `trustProxy.test.ts`, `expressMiddleware.test.ts` |
| Packaging | `packaging.test.ts` — Apache-2.0 + NOTICE + author |

## Fixtures

- `test/fixtures/awesomeJailbreakAttacks.json` — regenerated via `npm run fixtures:awesome-jailbreak`
- `test/fixtures/awesomeJailbreakTitles.json` — bibliography titles (metadata only)
- `test/fixtures/benignPrompts.json` — short benign prompts for accuracy floors
- `test/fixtures/evasionAttacks.json` — obfuscated / multilingual / split-payload evasions

## Honesty rules

- Do not add paper-title regexes to pass Awesome-Jailbreak tests.
- Prefer general detector fixes when a family fails.
- Document real gaps in `docs/LIMITATIONS.md` rather than hiding them.
