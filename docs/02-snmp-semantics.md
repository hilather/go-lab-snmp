# 02 — SNMP semantics

Status: Proposed
Owners: Data Plane
Last reviewed: 2026-09-05

LabSNMP speaks SNMP on the wire. It does not speak net-snmp `snmpd.conf`, AgentX, or a SMIv2 compiler.

## Transports

| Transport | Port | Role |
|---|---|---|
| UDP | 161 | Agent — Response to Get/GetNext/GetBulk/Set |
| UDP | 162 | Sink — receive Trap v1, SNMPv2-Trap, Inform |
| TCP RFC 3430 | 161/tcp, 162/tcp | BER-length framing: one SNMP SEQUENCE (identifier+length, **not** a 32-bit prefix). `snmpwire.ReadTCP` / `WriteTCP`. |
| DTLS 1.2 record layer | 10161/udp, 10162/udp | Inner PDU is community or USM. TLSTM/TSM is not implemented. Not RFC 6353. |

RFC 3430 §2.1: each TCP message is one BER-encoded SNMP message. A framed Get starts with `0x30`. On loss of framing (truncated, indefinite length, ASN.1 parse error) `ReadTCP` returns an error so the server can close the connection. 1.1 does not pipeline requests on one TCP connection. `TCP_NODELAY` is an agent-listener concern, not `snmpwire`. Default `maxMessageBytes` (64KiB) already satisfies RFC 3430 §2.2 ≥8192.

Identity is **community string** (v1/v2c) or **USM user** (v3), not client IP. Docker `userland-proxy` NAT collision does not collapse maps. Trap records still store `remoteAddr` best-effort. This file must contain the phrases `NAT collision` and `userland-proxy`.

## Versions

| Version | Auth | PDUs LabSNMP answers / accepts |
|---|---|---|
| SNMPv1 (RFC 1157) | community | Get, GetNext, Set, Trap-v1 |
| SNMPv2c (RFC 1901/3416) | community | Get, GetNext, GetBulk, Set, SNMPv2-Trap, Inform |
| SNMPv3 (RFC 3412/3414/3416) | USM user | same PDUs as v2c plus Report |

GetBulk on v1 is a parse error (not a PDU). Walk is not a PDU; GETNEXT/GETBULK correctness *is* walk.

## Community resolution (v1/v2c)

1. Decode community octet string.
2. Match against compiled communities by **string bytes**, unique.
3. No match → drop silently (v1/v2c has no report). Metric `labsnmp_auth_fail_total{version="v1|v2c"}`.
4. Version not in that community's `versions` list → drop.
5. Resolve `map` name → compiled tree.
6. Access `read` forbids Set (error-status `noAccess` / v1 `noSuchName`).

`communities[].name` is a DNS-label row id (REST/MCP/UI). The wire community octet string is the trimmed contents of the required `communityFile`. Inline `community:` / `secretFile` on a community row is an unknown or validate error.

## USM resolution (v3, RFC 3414)

1.0 algorithms only:

| Direction | Allowed |
|---|---|
| auth | `none`, `MD5`, `SHA-1`, `SHA-256` |
| priv | `none`, `DES`, `AES-128` |
| level | `noAuthNoPriv`, `authNoPriv`, `authPriv` |

Auth without a protocol, priv without auth, or unknown protocol → validate error.

EngineID: `spec.engine.engineID` hex, or derived from hostname + fixed lab prefix. Time window: RFC 3414 150-second window; LabSNMP uses a process clock, never `settimeofday`.

Unknown user / bad engine / failed auth → Report PDU when possible, else drop. Do not leak whether the user exists in v1/v2c style; v3 Report uses standard `usmStats` counters in the response.

VACM in 1.0 is flattened: user → access + named map. No independent group/view DSL.

## PDU behavior

### Get

Each varbind looked up in the map. Missing: v1 `noSuchName` (error-status + error-index); v2c/v3 `noSuchObject` or `noSuchInstance` in the varbind.

### GetNext

Lexicographic successor of the requested OID in the compiled tree, respecting the view (the whole map is the view in 1.0). End: v1 `noSuchName`; v2c/v3 `endOfMibView`.

### GetBulk (v2c/v3)

`non-repeaters` then `max-repetitions` as RFC 3416. Cap `max-repetitions` at `spec.agent.maxRepetitions` (default 100) to bound work.

### Set

RFC 3416 two-phase / all-or-nothing:

1. Identity `access` must be `read-write` (else `noAccess` / v1 `noSuchName`; error-index of the first varbind).
2. Phase 1 — `CheckSet` **every** varbind against overlay+bootstrap: leaf `access: write`, type, range/size, not `valueFrom: uptime`. On the first failure return that error-status and **1-based error-index**. Overlay is **unchanged**.
3. Phase 2 — only if every varbind passed: apply all overlay writes, then `storeGeneration++` **once**. GET after SET sees overlay.
4. Reset drops overlay.

Errors: `notWritable`, `wrongType`, `wrongLength`, `wrongValue`, `noAccess`, `genErr`, plus v1 `noSuchName` / `tooBig`.

### Trap sink

- TRAPv1, SNMPv2-TRAP stored with raw + parsed varbinds.
- INFORM: store then `WriteTo` a Response to the source address. Never Dial.
- Unknown community/user: drop + metric. Do not store unauthenticated traps by default (`spec.traps.acceptUnauthenticated` default false).

## OID map

A map is a named collection of scalars and table rows. 1.0 has **no MIB compiler**. Names (`sysDescr`) are aliases for humans and UI; the wire key is the dotted OID.

Shipped example map `system-if` (examples only, not hardcoded in the engine) covers SNMPv2-MIB system group + a tiny ifTable. Testers clone it.

## What this is not

- AgentX subagent
- SMIv2 imported MIBs
- Notification originator
- SNMP proxy
- Manager that walks some other agent
