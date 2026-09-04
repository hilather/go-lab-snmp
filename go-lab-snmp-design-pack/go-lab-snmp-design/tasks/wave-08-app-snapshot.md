# APP-001 — Snapshot, plan/apply/reset, overlay

Status: not-started
Depends: CFG-001, MAP-001, TRAP-001
Owns: internal/app, internal/compiler, internal/snapshot, overlay

## Goal
Compile snapshot, swap atomically, plan/apply closed ops, reset drops overlay + traps.

## Scope
- Closed operations from docs/04
- expectedRevision + idempotency
- oids:set path shares overlay with SNMP SET
- storeGeneration

## Tests
revision mismatch; idempotent apply; reset restores bootstrap values after SET; traps wiped.
