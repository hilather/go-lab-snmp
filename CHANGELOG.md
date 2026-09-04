# Changelog

## [Unreleased]

### Added

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
