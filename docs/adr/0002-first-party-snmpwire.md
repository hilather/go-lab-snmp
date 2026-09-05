# ADR 0002 — First-party snmpwire

Status: Accepted

In-tree BER/PDU codec. No gosnmp, gosmi, or net-snmp types in `internal/model`. Test clients may use net-snmp binaries and gosnmp in `_test.go` / `internal/snmptest` only.
