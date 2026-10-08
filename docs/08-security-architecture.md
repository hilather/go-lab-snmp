# 08 — Security architecture

Status: Proposed
Owners: Security
Last reviewed: 2026-10-07
Related ADRs: 0005, 0016

## Bearer

`spec.auth.mode: bearer` only. Tokens are file refs, ≥32 bytes, SHA-256
digest compare (`crypto/subtle`). No HTTP Basic, no OAuth PRM. Roles
are `administrator` and `reader` and expand to `snmp.read`,
`snmp.write`, `snmp.admin`, `snmp.audit.read`. `snmp.admin` satisfies
every scope. Management bind fails closed with zero usable tokens
unless `--management-listen=off`. mcp-stdio binds the process to the
`--token-file` token id. Each tool call re-reads that id from the live
verifier. A reset that demotes the id drops `snmp.admin` on the next
call. Removing the id denies every scoped tool. HTTP MCP with a bearer
header still authenticates that header.

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
- Per-source agent and trap datagram buckets use the management idle
  window (30s, or four burst-refill intervals when that is longer) and
  are deleted from inside `allow`. Memory is bounded by that idle
  window (30 s / four refills) and the per-datagram eviction scan is
  proportional to the number of sources seen within that window; it is
  not a hard cap.
- No trap forward (no amplifier).
- RFC 3430 TCP is cleartext. DTLS 1.2 is a record layer on IANA
  10161/10162; inner PDU is still community or USM. TLSTM/TSM is
  not implemented. RFC 6353 TLS-over-TCP is residual.

## Threat model

| Path | Confidentiality | Integrity | View identity |
|---|---|---|---|
| UDP 161/162 v1/v2c | none (community on wire) | none | communityFile bytes |
| UDP v3 USM | AES-128 if authPriv | HMAC | USM user |
| TCP 161/162 | **none** (RFC 3430 cleartext) | none beyond USM | same |
| DTLS + community | DTLS record encryption | DTLS + community still on inner PDU | community, **not** client cert |
| DTLS + USM | DTLS + optional USM priv | both | USM user |

Enabling DTLS does not encrypt leftover UDP listeners. The “no
cleartext” recipe is legal: `listeners.agent.enabled: false`,
`listeners.traps.enabled: false`, `tcp.enabled: false`,
`dtls.enabled: true` with certs. Serve does not exit 1 solely
because UDP agent is off. Default overlay still UDP.

Client cert (`clientCAFile`) is transport auth, not a map key.

## Secrets

Never in GET state, UI, logs at info, or metrics labels. Paths may
appear. Cert/key bytes never appear; `certFile` / `keyFile` /
`clientCAFile` paths may. `GET /v1/users` returns `secretFile`
paths, never file contents. Audit diffs redact `secretFile` /
`token` / `cookie` paths.
