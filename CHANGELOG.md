# Changelog

## [Unreleased]

### Added

- slog JSON logs and hand-rolled OpenMetrics (`internal/observability`): series `labsnmp_pdus_total`, `labsnmp_traps_total`, `labsnmp_store_messages`, `labsnmp_store_bytes`, `labsnmp_apply_total`, `labsnmp_http_requests_total`, `labsnmp_build_info`, `labsnmp_auth_fail_total`. Ready = snapshot installed AND every enabled data-plane listener bound AND (management bound or `--management-listen=off`). `GET /v1/metrics` when `metrics.publicPath` is true. `labsnmp healthcheck --url=`. Generated `api/metrics/v1alpha1.json`. No Prometheus client; secrets and client IPs never appear as labels (OBS-001).
- REST `/v1` adapter (`internal/control/rest`) over `app.Service` plus the frozen capability table (`internal/capabilities`). Every PARITY_REQUIRED route, unauthenticated health live/ready, `application/problem+json` (`urn:labsnmp:error:<code>`), K20 features catalog, generated `api/openapi/v1.json` and `api/capabilities/v1.json`. `--management-listen` binds HTTP (default still off). Auth is a stub until SEC-001 (API-001).
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

- `GET /v1/state:export?format=json` writes the canonical document (same shape as YAML). `POST /v1/traps:wait` is capped by `spec.traps.maxWait`, not the 30s management request timeout.
- Community wire string is trimmed `communityFile` contents (K4). Inline `community:` / `secretFile` on communities reject.
- `valueFrom` is `uptime` (ADR 0011), not `processUptime`.
- START-HERE.md working path includes `labsnmp validate --config testdata/config/valid/full.yaml`.
- `labsnmp validate` prints field-violation paths. Map object integers stay
  integer-typed (including `counter64` above 2^53). `valueFrom: uptime`
  requires `type: timeTicks` and `access: read`.
