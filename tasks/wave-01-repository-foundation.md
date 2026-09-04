# FND-001 — Repository foundation

Status: not-started
Depends: none
Owns: repo root, cmd/labsnmp stub, Makefile, CI, docs skeleton

## Goal
Checkout builds, `labsnmp version` works, unimplemented Make targets exit 1.

## Scope
- go.mod module github.com/hilather/go-lab-snmp, Go 1.26
- Apache-2.0 LICENSE
- Package dirs from docs/01 with package comments only
- Makefile targets from AGENTS.md
- CI: format lint unit race fuzz-smoke docs changelog
- START-HERE README AGENTS CHANGELOG CONTRIBUTING SECURITY
- internal/buildinfo, internal/testutil

## Non-scope
Codec, listeners, REST, UI.

## Tests
go test ./... passes; no required target is a no-op; at least one race-sensitive test.

## Acceptance
linux/amd64 build; no import cycles; no gosnmp dependency in go.mod yet.
