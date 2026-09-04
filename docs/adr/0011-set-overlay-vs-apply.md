# ADR 0011 — SET overlay vs apply

Status: Accepted

SNMP SET and REST `oids:set` write an overlay. They are not apply verbs. Reset discards overlay. `valueFrom: uptime` is never writable.
