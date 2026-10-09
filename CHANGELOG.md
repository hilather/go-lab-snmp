# Changelog

All notable user-visible and operator-visible changes are recorded here.

## [Unreleased]

### Added

- None.

### Changed

- Go toolchain pinned to go1.26.9 (ADR 0017): `go.mod`
  `toolchain go1.26.9`, CI setup-go `go-version` 1.26.9, and the image
  `golang:1.26.9-alpine` (was floating `golang:1.26-alpine`), matching
  the rest of the go-lab family; 1.26.0-1.26.8 lack the stdlib
  security fixes for GO-2026-6603–6605, GO-2026-6607–6613 and
  GO-2026-6617. golang.org/x/crypto v0.48.0 -> v0.56.0 (x/sys
  v0.41.0 -> v0.47.0, x/net v0.49.0 -> v0.57.0) clears the fixable
  govulncheck advisories; `go.mod` now reads `go 1.26.0` (still the
  1.26 language); the one remaining module-level
  finding GO-2026-5932 (x/crypto openpgp) has no fix and is not
  reachable.
- Web development dependency `source-map-js` updates from 1.2.1 to 1.2.2
  (GHSA-68fv-2mgg-jv7q, high: event-loop denial of service through
  indexed source-map section offsets). Lockfile only; the built web
  assets are byte-identical.
- Web development dependency `undici` updates from 8.10.0 to 8.10.2 (via
  jsdom; GHSA-rfgv-xxqx-mfg5, GHSA-w293-vg96-wgc3 and
  GHSA-vp8m-p9jh-q5pm high, plus eight moderate or low undici
  advisories). Lockfile only; the built web assets are byte-identical.

### Fixed

- mcp-stdio re-authenticates its startup bearer on each call. A same-id secret rotation revokes the stdio process. Demoting or removing that secret drops the corresponding authority on the next tool call. The process acts as whatever principal the startup secret authenticates as.
- A failed reset restores data-plane listeners and the management listener to the snapshot that is still active. A management bind error no longer leaves sockets on the candidate addresses. A trap-policy failure puts management back only when that rebind already succeeded.
- A reset that turns management off or moves it returns without waiting on its own request. The old management server stops accepting at once and drains in the background for up to 5s, then remaining connections are closed. Process shutdown also waits for that background drain, bounded by --shutdown-timeout. A second shutdown of that detached server does not panic.
- A failed reset applies trap policy before it wipes the SET overlay, trap inbox, or query ring. A ReplaceCaps failure leaves that ephemeral state and the active snapshot in place.
- Agent and trap per-source datagram limiters drop idle buckets, using the same idle window as the management limiter. The idle scan runs at most once per sweep interval (idle window / 4, at least 1s). Each map is capped at 1024 buckets; a new source at the cap pays one bounded walk to evict the oldest bucket. Existing sources skip that walk.
- An agent datagram limiter built with a non-positive rate uses 1 per second, so a zero rate stays limited and a later rate update still applies.
- CI runs on `v*` tags and the tag release gate requires that tag's own completed push run. It fails when that newest matching run is still in progress, and a pull_request run or a main-branch push of the same SHA does not satisfy the gate. release.yml passes the tag and the notes path in as environment variables. The changelog check is skipped on tag pushes.
- Reusing an idempotency key with a different expectedRevision is idempotency_conflict. A retry with the same expectedRevision still returns the cached apply.

### Removed

- None.

## [1.1.0] - 2026-09-05

Notes: [docs/releases/v1.1.0.md](docs/releases/v1.1.0.md). TLS-001 (RFC 3430 TCP + DTLS 1.2 record layer) is no longer deferred.

### Added

- Agent RFC 3430 TCP and DTLS 1.2 record-layer listeners
  (`internal/snmpagent`). pion/dtls v3.1.8 with AEAD cipher suites,
  live CIDR admission, and BER TCP framing. TCP-only (UDP off) is
  supported.
- Trap/inform RFC 3430 TCP and DTLS 1.2 record-layer listeners
  (`internal/snmpsink`). INFORM and v3 Report share one ack path
  (`WriteTCP` / `Write` on the accepted connection, never Dial).
  Store-then-ack is unchanged (ADR 0007).
- v1.1 residual increment design (`IMPLEMENTATION-DESIGN-v1.1.md`),
  ADR 0016 (RFC 3430 TCP BER-length framing; DTLS 1.2 record layer on
  10161/10162, not TLSTM/TSM), and the v1.1 task board (FND-110).
- TCP/DTLS listener fields are schema-legal: `tcp.enabled` /
  `dtls.enabled` validate under per-listener address rules and
  file-ref certs (CFG-110).
- Snapshot compiles TCP/DTLS listener fields. Ready overlays Off
  from the active snapshot so disabled transports do not fail Ready.
  `GET /v1/status` may list `agent-tcp` / `traps-tcp` /
  `agent-dtls` / `traps-dtls` when enabled (address `off` when that
  plane is disabled). Gauge `labsnmp_listeners_bound` (APP-110).
- RFC 3430 BER TCP framing in `internal/snmpwire`: `ReadTCP` /
  `WriteTCP` frame one SNMP SEQUENCE by identifier+length. A framed
  Get starts with `0x30`.
- `labsnmp serve --dtls-listen` / `--dtls-trap-listen` (`ADDR|off`).
  Serve may start with agent UDP off if TCP or DTLS agent is on.
  Bind failure of any enabled data-plane listener is exit 1. Image
  `EXPOSE 161/tcp 162/tcp` (not `10161/udp`). Smoke compose stays
  UDP `:1161`/`:1162`.
- Operator SPA Status and Overview show Agent TCP / Agent DTLS
  dt/dd when `status.listeners` includes `agent-tcp` / `agent-dtls`.
  Features page still twelve ids. No new capability IDs (UI-110).
- GHCR publish on `v*` tags is a multi-arch manifest list
  (`linux/amd64`, `linux/arm64`). CI unit jobs stay amd64; arm64 is
  publish-only. `latest` remains non-prerelease tags only. The digest
  of the manifest list is the pin.
- Release notes `docs/releases/v1.1.0.md` (GA-110).

### Changed

- `tls_unsupported` is no longer emitted on `tcp`/`dtls` enable.
  Missing DTLS certs are `validation_failed`/`required`. Identities
  are required when any agent-plane listener will bind. AGENTS §11
  and known-limitations match 1.1 (TLSTM/TSM residual; TLS-over-TCP
  residual). Catalog `tls_unsupported` is retained for TLS-over-TCP.
- D12, docs/08 threat table, labinfo `tls` note, and README match
  v1.1: TCP/DTLS record layer is no longer deferred; TLSTM/TSM and
  TLS-over-TCP remain residual. Integrator example Ref is `v1.1.0`.
- Lab overlay (`examples/labsnmp.yaml`) keeps `tcp.enabled` /
  `dtls.enabled` false. v1.1 can enable TCP/DTLS with file-ref
  certs; this BOM does not. Integrator pin remains out of band.

### Fixed

- Reset rebinds UDP agent and trap sockets (bind-new-first). Changing
  bootstrap `listeners.agent.address` / `traps.address` then Reset moves
  the PacketConn. An empty desired UDP address stops that listener.
  A failed new bind leaves the old sockets serving (U2).
- INFORM acknowledgements increment `InformAck` before `WriteTo` so
  the counter cannot race the reply (`internal/snmpsink`). Store-then-ack
  is unchanged (ADR 0007).

### Removed

- None.

## [1.0.0] - 2026-09-05

Notes: [docs/releases/v1.0.0.md](docs/releases/v1.0.0.md). TLS-001 stays deferred.

### Added

- GA hardening: expanded snmpwire BER + OID + INTEGER + community-encode fuzz, GETNEXT+SET+trap soak (CI-safe 2s; `LABSNMP_SOAK_DURATION` for a longer pre-tag run), `docs/releases/v1.0.0.md`, known-limitations residual lock, `scripts/release-gate`, tag-gate + GHCR publish on `v*`, and `make security-scan` via govulncheck v1.1.4 (GA-001).
- Integration-lab BOM (`examples/labsnmp.yaml`, labinfo id `labsnmp`, Jungle `labsnmp.json`): copy-paste overlay for mcp-integration-lab. Residual host ports 10161/10162/18161, env `LABSNMP_REST_PORT` (not `LABSNMP_MGMT_PORT`), `NET_BIND_SERVICE`, healthcheck, maps `public-if`/`private-if`, user `alice`. Integrator pin is out of band; this repo does not implement `vendor.go` (SWAP-001).
- Operator SPA (Vite + React 19) over REST `/v1`: login, overview, maps
  (tree + `oids:set` overlay), communities/users (secrets never shown),
  trap inbox (no send-trap), queries, plan/apply, gated reset, audit,
  features, status. Cookie `labsnmp_session` + CSRF `X-LabSNMP-CSRF` in
  process memory; Vitest `assertNoTokenStorage`. `ui.enabled: false` is
  404 `application/problem+json`. Committed `internal/web/dist` is a real
  Vite tree. Mira checklist in docs/12 signed off for 1.0.0 (UI-001).
- Scratch image UID `65532:65532` (`Dockerfile`, `golang:1.26-alpine`, `CGO_ENABLED=0`, no Node stage). Image CMD `serve --config=/etc/labsnmp/config.yaml --management-listen=:8088` with exec HEALTHCHECK `GET /v1/health/ready`. `examples/compose.smoke.yaml` and `make test-container` bind `:1161`/`:1162` with `cap_drop: ALL`. Serve `--shutdown-timeout` defaults to 10s; `--pid-file` writes after binds (write failure shuts down and exits 1). Health stays unauthenticated; other `/v1` routes require bearer (SEC-001) (DEP-001).
- Streamable HTTP MCP adapter (`internal/control/mcp`) over `app.Service`: `snmp_*` tools, `labsnmp://` resources, protocol `2026-07-28`, `POST /mcp` with `Stateless: true`, SDK v1.7.0 only in the adapter, `labsnmp mcp-stdio --config --token-file`, and `make test-parity`. MCP does not HTTP-call REST. `allowLegacyClients` defaults false; lab overlay true (MCP-001).
- Management bearer from `spec.auth.tokens[].secretFile` (≥32 bytes, SHA-256 digest compare), cookie `labsnmp_session` (HttpOnly SameSite=Lax Path=/), CSRF `X-LabSNMP-CSRF` in process memory, exact-match Origins, and an in-memory audit ring. Every `/v1` route except health (and metrics if `publicPath`) requires bearer or session. Users list keeps `secretFile` paths and never file contents (SEC-001).
- slog JSON logs and hand-rolled OpenMetrics (`internal/observability`): series `labsnmp_pdus_total`, `labsnmp_traps_total`, `labsnmp_store_messages`, `labsnmp_store_bytes`, `labsnmp_apply_total`, `labsnmp_http_requests_total`, `labsnmp_build_info`, `labsnmp_auth_fail_total`. Ready = snapshot installed AND every enabled data-plane listener bound AND (management bound or `--management-listen=off`). `GET /v1/metrics` when `metrics.publicPath` is true. `labsnmp healthcheck --url=`. Generated `api/metrics/v1alpha1.json`. No Prometheus client; secrets and client IPs never appear as labels (OBS-001).
- REST `/v1` adapter (`internal/control/rest`) over `app.Service` plus the frozen capability table (`internal/capabilities`). Every PARITY_REQUIRED route, unauthenticated health live/ready, `application/problem+json` (`urn:labsnmp:error:<code>`), K20 features catalog, generated `api/openapi/v1.json` and `api/capabilities/v1.json`. `--management-listen` binds HTTP (default still off).
- Snapshot compile and atomic swap (`internal/compiler`, `internal/snapshot`) plus HTTP-less `internal/app` plan/apply/reset. Closed apply ops from docs/04, `expectedRevision` + idempotency, `oids:set` sharing the SNMP SET overlay, and Reset that rereads bootstrap / drops overlay / wipes traps+queries without writing the file (APP-001).
- UDP/162 trap/inform sink (`internal/snmpsink` + `internal/store` ring): `ListenPacket`, TRAPv1 / SNMPv2-TRAP / INFORM including v3 USM, INFORM `WriteTo` (never Dial), bounded ring with wait/wipe, `acceptUnauthenticated` default false, ULID ids, and `labsnmp serve --trap-listen` (empty uses YAML `traps.enabled` / `traps.address`; `off` disables). Ready’s trap clause is on (TRAP-001).
- UDP/161 agent (`internal/snmpagent`): `ListenPacket`, CIDR+rate admission, community isolation, GET/GETNEXT/GETBULK/SET with two-phase overlay SET, `valueFrom: uptime` (1s → TimeTicks 100), and thin `labsnmp serve --config --snmp-listen` with `--management-listen` default off. Loads `compiler.Compile` + `snapshot.Store` (APP-001; AGENT-001 hand-wire removed).
- Bounded SNMPv3 USM (`internal/usm`): noAuthNoPriv / authNoPriv / authPriv with HMAC-MD5-96, HMAC-SHA-96, HMAC-SHA-256-192 and CBC-DES / CFB128-AES-128; RFC 3414 engine discovery Reports (`usmStatsUnknownEngineIDs` / `unknownUserNames` and the other usmStats counters); localized keys from passphrases; 150-second process-clock window. HMAC/decrypt here; WIRE keeps ciphertext as OCTET STRING (USM-001).
- First-party SNMPv1/v2c/v3 BER codec (`internal/snmpwire`): Get/GetNext/GetBulk/Set/Response/Trap-v1/SNMPv2-Trap/Inform/Report, v3 ciphertext as OCTET STRING, request-id preservation, max-message cap, constructed packet goldens plus skip-if-missing net-snmp `-d` interop, and decoder + OID fuzz (WIRE-001).
- Lex-ordered OID instance tree: GET, GETNEXT, GETBULK, and SET-check (MAP-001).
- Fail-closed `labsnmp.dev/v1alpha1` YAML: KnownFields, `communityFile`-required communities, `labsnmp validate` / `canonicalize`, and config fixtures (CFG-001).
- ADR 0015: community strings are file refs; `name` is a DNS-label row id.
- Repository foundation: `labsnmp version`, Makefile, CI, living docs, and package stubs (FND-001).
- Design pack for LabSNMP: architecture, ADRs, agent waves, and mcp-integration-lab evaluation.

### Changed

- `GET /` is 200 SPA HTML when `spec.ui.enabled` is true (and the embed is live); 404 `application/problem+json` when false.
- Operator SPA Mira checklist signed off for 1.0.0 from UI-001 tests
  (pages, no localStorage tokens, CSRF, `ui.enabled: false` 404, no
  send-trap). Empty-state copy and skip-link focus on list pages. No
  new capability IDs (UI-001).
- `GET /v1/queries` items are camelCase (`type`, `identity`, `decision`,
  `errorStatus`), matching docs/06 and the operator SPA.
- Apply/reset reloads bearer identity, `allowedOrigins`, and `metrics.publicPath` from the live snapshot. Unreadable or empty `spec.auth` drops the previous verifier instead of keeping old tokens. Token files resolve CWD then the bootstrap directory. OpenAPI documents cookie `labsnmp_session` and header `X-LabSNMP-CSRF`.
- `GET /v1/state:export?format=json` writes the canonical document (same shape as YAML). `POST /v1/traps:wait` is capped by `spec.traps.maxWait`, not the 30s management request timeout.
- Community wire string is trimmed `communityFile` contents (K4). Inline `community:` / `secretFile` on communities reject.
- `valueFrom` is `uptime` (ADR 0011), not `processUptime`.
- START-HERE.md working path includes `labsnmp validate --config testdata/config/valid/full.yaml`.
- `labsnmp validate` prints field-violation paths. Map object integers stay
  integer-typed (including `counter64` above 2^53). `valueFrom: uptime`
  requires `type: timeTicks` and `access: read`.
