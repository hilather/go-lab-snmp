# WIRE-001 — First-party SNMP codec

Status: done
Depends: CFG-001
Owns: internal/snmpwire, testdata/packets

## Goal
Encode/decode SNMPv1, v2c, v3 messages and Get/GetNext/GetBulk/Set/Response/Trap/Inform/Report PDUs without leaking library types.

## Scope
- BER subset required by SNMP
- Types listed in docs/03
- Version dispatch
- Request-id preservation
- Max message size cap

## Non-scope
USM crypto (USM-001), UDP listen, MIB tree.

## Tests
Constructed goldens in testdata/packets (1.0 corpus); skip-if-missing
net-snmp `-d` interop in `_test.go`; fuzz-smoke decoder + OID parse;
never import gosnmp.

## Acceptance
Round-trip encode(decode(packet)) for each PDU class in testdata/packets.
