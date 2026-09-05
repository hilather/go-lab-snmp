# 08 — Security architecture

Status: Proposed
Owners: Security
Last reviewed: 2026-09-04
Related ADRs: 0005

## Bearer

`spec.auth.mode: bearer` only. Tokens are file refs, ≥32 bytes, SHA-256
digest compare (`crypto/subtle`). No HTTP Basic, no OAuth PRM. Roles
are `administrator` and `reader` and expand to `snmp.read`,
`snmp.write`, `snmp.admin`, `snmp.audit.read`. `snmp.admin` satisfies
every scope. Management bind fails closed with zero usable tokens
unless `--management-listen=off`.

Every `/v1` route except health live/ready (and `GET /v1/metrics` when
`observability.metrics.publicPath` is true) requires bearer or a
cookie session. MCP is never public without a token.

## SPA session

Cookie `labsnmp_session` HttpOnly SameSite=Lax Path=/. Idle 4h,
absolute 12h, max 64 sessions. CSRF header `X-LabSNMP-CSRF` on
cookie-authenticated mutations. CSRF secret is process memory only —
never localStorage / sessionStorage. See [12-web-ui.md](12-web-ui.md).

## Origins

Missing Origin is allowed. Loopback Origins (`http://127.0.0.1:8088`,
`http://localhost:5173`) are allowed. A present non-loopback Origin
must be an exact `spec.management.allowedOrigins` entry
(scheme+host+port). `*` is not allowed. Default `allowedOrigins: []`
(deny-all for non-loopback). `originAllowlist` is an unknown YAML
field.

## Data plane

- v1/v2c: community string from file. Treat as a shared secret.
  Prefer long random values in non-dev profiles.
- v3: USM. Time window 150s. Localized keys at compile.
- Trap sink: unauthenticated beyond community/user on the PDU.
  Anyone who can reach 162 can fill the store — admission CIDRs.
- No trap forward (no amplifier).

## Secrets

Never in GET state, UI, logs at info, or metrics labels. Paths may
appear. `GET /v1/users` returns `secretFile` paths, never file
contents. Audit diffs redact `secretFile` / `token` / `cookie` paths.
