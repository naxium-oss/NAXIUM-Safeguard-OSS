# Limitations (read this before deploying)

NAXIUM-Safeguard-OSS is a **heuristic, local, pattern/lexicon/TF-IDF-based**
layer. It is not a machine-learned classifier trained on adversarial data at
scale, and it does not call out to any external moderation model by default.

What this means concretely:

1. **Novel phrasing can still beat heuristics.** Anything not resembling a known
   jailbreak template or lexicon term can slip through, especially at low
   security levels. Layers that help include: regex patterns, intent-feature
   co-occurrence, innocent-disguise framing, fuzzy tokens, n-gram overlap,
   slot-fill templates, code/markup smuggling, many-shot repetition density,
   destructive-command heuristics, and TF-IDF similarity against a local
   attack corpus. TF-IDF is not a neural embedding model — creative rewrites
   can still miss.
2. **False positives are real**, especially at level 8-10. Security research,
   fiction writing, medical/legal professionals, and pentesters will get
   blocked on legitimate use. That is the tradeoff of high strictness.
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

If your threat model requires stronger guarantees, pair this with a hosted
moderation API and/or a fine-tuned safety classifier, and treat NAXIUM as
the fast, free, local, first line of defense — not the last one.
