# 03 — MIB tree and trap store

Status: Proposed  
Last reviewed: 2026-09-04

## MIB tree

Each named map compiles to a sorted slice of instance OIDs.
Lookups are binary search. GETNEXT is the successor.

SET writes `overlay[oid] = newValue` on that map. GET reads
overlay first, then bootstrap. `valueFrom: uptime` is computed
at read time from process start (or snapshot compile time —
stamp `uptimeEpoch` in the snapshot) and ignores overlay.

REST `POST /v1/maps/{name}/oids:set` is the same overlay write
with admin scope, so testers can flip `ifOperStatus` without an
SNMP SET from a SUT.

Reset: overlay cleared, trap store wiped, bootstrap values live
again. `storeGeneration` increments.

## Trap store

LabMail-shaped ring:

- id ULID
- receivedAt
- version, pduType (`trapv1` \| `trapv2` \| `inform`)
- community or user
- remoteAddr (best-effort under Docker userland-proxy)
- enterprise / notification OID
- varbinds
- raw
- parseWarning

Caps: `maxMessages`, `maxBytes`, `fullPolicy: evict_oldest|reject`.
`Wait(ctx, filter, timeout)` for agents.

No durable spool. No forward.
