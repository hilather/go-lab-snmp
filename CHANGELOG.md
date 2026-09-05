# Changelog

## [Unreleased]

### Added

- Bounded SNMPv3 USM (`internal/usm`): noAuthNoPriv / authNoPriv / authPriv with HMAC-MD5-96, HMAC-SHA-96, HMAC-SHA-256-192 and CBC-DES / CFB128-AES-128; RFC 3414 engine discovery Reports (`usmStatsUnknownEngineIDs` / `unknownUserNames` and the other usmStats counters); localized keys from passphrases; 150-second process-clock window. HMAC/decrypt here; WIRE keeps ciphertext as OCTET STRING (USM-001).
- First-party SNMPv1/v2c/v3 BER codec (`internal/snmpwire`): Get/GetNext/GetBulk/Set/Response/Trap-v1/SNMPv2-Trap/Inform/Report, v3 ciphertext as OCTET STRING, request-id preservation, max-message cap, constructed packet goldens plus skip-if-missing net-snmp `-d` interop, and decoder + OID fuzz (WIRE-001).
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
