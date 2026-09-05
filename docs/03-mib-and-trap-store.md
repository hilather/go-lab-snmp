# 03 — MIB tree and trap store

Status: Proposed
Owners: Data Plane
Last reviewed: 2026-09-04

## MIB tree

Each named map compiles to a sorted slice of instance OIDs
(`internal/mibtree`). Lookups are binary search. GETNEXT is the
lexicographic successor. Duplicate OIDs are a compile error. An empty
`objects` list is legal (ADR 0008: explicit YAML maps, no SMIv2
compiler).

OID order is numeric on arcs, not string sort: `1.3.6` precedes
`1.3.6.1`, and `1.3.6` precedes `1.3.10`. A walk-equivalent GETNEXT
loop returns every leaf once.

### GET

Without a MIB compiler, exceptions are:

- exact instance → value
- request is a proper prefix of an instance (column/object, not an
  instance) → `noSuchInstance`
- an instance is a proper prefix of the request (GET under a scalar),
  or no overlap → `noSuchObject`

### GETNEXT

Successor in the compiled slice. Past the last instance →
`endOfMibView` (v1 maps this to `noSuchName` at the PDU layer).

### GETBULK

RFC 3416 non-repeaters then max-repetitions. Negative counts are 0.
Repetitions are capped at `spec.agent.maxRepetitions` (default 100).

### SET-check

`CheckSet` validates leaf `access: write`, type, and range/size. It
does not write. `valueFrom: uptime` is never writable (`notWritable`).
Missing OIDs are `notWritable` (1.0 has no row creation). Overlay apply
is the store, not the tree.

SET writes `overlay[oid] = newValue` on that map. GET reads
overlay first, then bootstrap. `valueFrom: uptime` is computed
at read time from process start (or snapshot compile time —
stamp `uptimeEpoch` in the snapshot) and ignores overlay.
TimeTicks are hundredths of a second:
`uint32((now.Sub(uptimeEpoch) / 10ms) % (1<<32))`.

REST `POST /v1/maps/{name}/oids:set` is the same overlay write
with admin scope, so testers can flip `ifOperStatus` without an
SNMP SET from a SUT.

Reset: overlay cleared, trap store wiped, bootstrap values live
again. `storeGeneration` increments.

1.0 YAML types (camelCase): `integer`, `octetString`,
`objectIdentifier`, `null`, `ipAddress`, `counter32`, `gauge32`,
`unsigned32`, `timeTicks`, `opaque`, `counter64`.

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
