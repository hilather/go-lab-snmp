# TRAP-001 — UDP 162 sink

Status: not-started
Depends: WIRE-001
Owns: internal/snmpsink, trap half of internal/store

## Goal
Store TRAPv1, SNMPv2-TRAP, INFORM. ACK INFORM via WriteTo. Never Dial.

## Scope
- Bounded ring, wait, wipe
- acceptUnauthenticated default false
- parseWarning on best-effort

## Tests
AST no Dial; INFORM WriteTo to source; wait existing/inserted/timeout/wipe; unauth drop.

## Acceptance
snmptrap to :1162 then REST/MCP wait returns the record.
