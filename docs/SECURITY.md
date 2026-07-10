# Security notes (sidecar / HTTP)

## Authentication

- Set `NAXIUM_API_KEY` (min 8 characters). Comparisons use SHA-256 +
  `timingSafeEqual`.
- In `NODE_ENV=production`, the process **refuses to start** without an API key
  unless you explicitly set `NAXIUM_REQUIRE_API_KEY=0` / `false` / `off`
  (not recommended). Set `NAXIUM_REQUIRE_API_KEY=1` to require a key even in
  development.
- `docker-compose.yml` requires `NAXIUM_API_KEY` via `.env`.
- `GET /health` and `GET /v1/health` remain unauthenticated for probes.

## Rate limiting & session reset

- HTTP routes and Express middleware derive a `protectionKey` from `req.ip`
  (Express resolves this from `X-Forwarded-For` **only** when `trust proxy`
  is enabled via `NAXIUM_TRUST_PROXY=1` / `createApp({ trustProxy: true })`).
- When trust proxy is off, client-supplied `X-Forwarded-For` is ignored for
  rate/lockout keys (prevents spoofed-IP bypass).
- Client-supplied `context.sessionId` / `context.ip` are **not** used for
  rate-limit or lockout decisions on the HTTP surface.
- `POST /v1/session/reset` resets **only the caller’s** protection key.
- Request bodies are capped at **64KB** by default to bound detector CPU.

## Network binding

- Default listen host is `127.0.0.1` (`NAXIUM_HOST`). Docker sets `0.0.0.0`
  inside the container and publishes `127.0.0.1:8787` on the host.
- Container runs as non-root user `naxium`.

## Response surface

- Express middleware does **not** expose `riskScore` / categories by default
  (`exposeDetails: true` to opt in). Prefer not leaking detector feedback to
  untrusted clients.

## GuardResult.safe semantics

- `safe === true` for both `allow` and `flag`.
- `safe === false` for `block` and `lockout`.
- If you need to treat soft flags differently, check `result.action === 'flag'`.

## Reporting issues

- Heuristic **detection bypasses** are expected to some degree — file as
  enhancement issues with repro prompts (synthetic only). See
  `docs/LIMITATIONS.md` and `CONTRIBUTING.md`.
- For vulnerabilities in auth, binding, or dependencies, prefer a private
  advisory channel when available.
