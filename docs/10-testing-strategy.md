# 10 — Testing strategy

Status: Proposed
Owners: Testing
Last reviewed: 2026-09-04

Unit next to the package. Packet goldens in `testdata/packets` are
constructed valid messages (1.0 committed corpus). Skip-if-missing
net-snmp `-d` interop in `_test.go` supplements them when `snmp*`
tools are installed.
Interop: snmpget/walk/set/trap as tests via `internal/snmptest` and,
in `_test.go` only, net-snmp binaries if present (skip if missing).

AST fences: Dial, forbidden modules, forbidden exec basenames.
Config matrix under testdata/config. REST contracts. MCP parity.
Fuzz snmpwire. Soak GET/s. Container script on :1161/:1162
(`make test-container`; skip if Docker is missing; net-snmp CLI
interop skip if missing).
