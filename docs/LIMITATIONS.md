# Limitations (read this before deploying)

NAXIUM-Safeguard-OSS is a **heuristic, local** layer combining patterns, lexicons,
contrastive TF-IDF, a small on-device logistic intent model, and structural
heuristics. It is not a neural safety classifier trained on adversarial data at
scale, and it does not call out to any external moderation model by default.

What this means concretely:

1. **Novel phrasing can still beat heuristics.** Anything not resembling a known
   jailbreak template or lexicon term can slip through, especially at low
   security levels. Layers that help include: regex patterns (with cue gating),
   intent-feature co-occurrence, innocent-disguise framing, fuzzy tokens,
   boundary-aware character n-grams, slot-fill templates, code/markup smuggling,
   many-shot repetition density, destructive-command heuristics, contrastive
   TF-IDF against attack *and* benign corpora, multilingual override cues,
   config/DSL injection detection, payload-split reconstruction, a committed
   logistic intent model, and session-level crescendo tracking. None of these
   are embeddings or LLM judges — creative rewrites can still miss.
2. **False positives are real**, especially at level 8–10, though stance
   dampening and corroboration caps reduce blocks on clearly defensive or
   educational asks. Security research, fiction writing, medical/legal
   professionals, and pentesters may still be flagged on edge-case wording.
3. **This is one layer, not a system.** Use it alongside: your model
   provider's own moderation endpoint (if available), human review queues
   for high-risk categories, sandboxed tool execution, least-privilege
   credentials for agents, and monitoring/alerting.
4. **The CSAM hard-block cannot be disabled**, even at security level 0. This
   is a deliberate, documented exception — not hidden behavior.
5. **No claims of "unbypassable" or "100% jailbreak-proof"** are made or
   should be made about this tool. If you see that claim in downstream
   marketing, it is false.
6. **SSRF checks are static.** Hosts are parsed from the request text only —
   there is no DNS resolution, so DNS-rebinding and newly registered metadata
   hostnames can still slip through. Pair with network egress controls.
7. **Payload size is capped** (default 64KB on the HTTP sidecar). Extremely
   large prompts are rejected or truncated before heavy detectors run.
8. **The intent model is small and corpus-bound.** Retrain after changing
   `knownAttackCorpus.json` or `benignCorpus.json`; do not treat its score as
   ground truth outside the training distribution.

If your threat model requires stronger guarantees, pair this with a hosted
moderation API and/or a fine-tuned safety classifier, and treat NAXIUM as
the fast, free, local, first line of defense — not the last one.
