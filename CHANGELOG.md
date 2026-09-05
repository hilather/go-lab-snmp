# Changelog

## [Unreleased]

### Added

- UDP/162 trap/inform sink (`internal/snmpsink` + `internal/store` ring): `ListenPacket`, TRAPv1 / SNMPv2-TRAP / INFORM including v3 USM, INFORM `WriteTo` (never Dial), bounded ring with wait/wipe, `acceptUnauthenticated` default false, ULID ids, and `labsnmp serve --trap-listen` (empty uses YAML `traps.enabled` / `traps.address`; `off` disables). Ready’s trap clause is on (TRAP-001).
- UDP/161 agent (`internal/snmpagent`): `ListenPacket`, CIDR+rate admission, community isolation, GET/GETNEXT/GETBULK/SET with two-phase overlay SET, `valueFrom: uptime` (1s → TimeTicks 100), and thin `labsnmp serve --config --snmp-listen` with `--management-listen` default off. Hand-wire Runtime (no app/compiler/snapshot) (AGENT-001).
- Bounded SNMPv3 USM (`internal/usm`): noAuthNoPriv / authNoPriv / authPriv with HMAC-MD5-96, HMAC-SHA-96, HMAC-SHA-256-192 and CBC-DES / CFB128-AES-128; RFC 3414 engine discovery Reports (`usmStatsUnknownEngineIDs` / `unknownUserNames` and the other usmStats counters); localized keys from passphrases; 150-second process-clock window. HMAC/decrypt here; WIRE keeps ciphertext as OCTET STRING (USM-001).
- First-party SNMPv1/v2c/v3 BER codec (`internal/snmpwire`): Get/GetNext/GetBulk/Set/Response/Trap-v1/SNMPv2-Trap/Inform/Report, v3 ciphertext as OCTET STRING, request-id preservation, max-message cap, constructed packet goldens plus skip-if-missing net-snmp `-d` interop, and decoder + OID fuzz (WIRE-001).
- Lex-ordered OID instance tree: GET, GETNEXT, GETBULK, and SET-check (MAP-001).
- Fail-closed `labsnmp.dev/v1alpha1` YAML: KnownFields, `communityFile`-required communities, `labsnmp validate` / `canonicalize`, and config fixtures (CFG-001).
- ADR 0015: community strings are file refs; `name` is a DNS-label row id.
- Repository foundation: `labsnmp version`, Makefile, CI, living docs, and package stubs (FND-001).
- Design pack for LabSNMP: architecture, ADRs, agent waves, and mcp-integration-lab evaluation.

### Changed

- Community wire string is trimmed `communityFile` contents (K4). Inline `community:` / `secretFile` on communities reject.
- `valueFrom` is `uptime` (ADR 0011), not `processUptime`.
- START-HERE.md working path includes `labsnmp validate --config testdata/config/valid/full.yaml`.
- `labsnmp validate` prints field-violation paths. Map object integers stay
  integer-typed (including `counter64` above 2^53). `valueFrom: uptime`
  requires `type: timeTicks` and `access: read`.
