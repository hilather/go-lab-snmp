# 10 — Testing strategy

Status: Proposed
Owners: Testing
Last reviewed: 2026-09-05

Unit next to the package. Packet goldens in `testdata/packets` are
constructed valid messages (1.0 committed corpus). Skip-if-missing
net-snmp `-d` interop in `_test.go` supplements them when `snmp*`
tools are installed.
Interop: snmpget/walk/set/trap as tests via `internal/snmptest` and,
in `_test.go` only, net-snmp binaries if present (skip if missing).

AST fences: Dial, forbidden modules, forbidden exec basenames.
Config matrix under testdata/config. REST contracts. MCP parity.
Fuzz snmpwire decoder, OID parse, BER INTEGER, and community encode
(`make test-fuzz-smoke`). Soak GETNEXT+SET+trap is CI-safe (default
2s; `LABSNMP_SOAK_DURATION` for a longer pre-tag run). Container
script on :1161/:1162 (`make test-container`; skip if Docker is
missing; net-snmp CLI interop skip if missing). `make security-scan`
is govulncheck. Tag-gate requires green CI on the exact SHA before
`v1.0.0`.
