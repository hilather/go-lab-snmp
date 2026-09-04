# AGENT-001 — UDP 161 responder

Status: not-started
Depends: WIRE-001, MAP-001, USM-001
Owns: internal/snmpagent

## Goal
ListenPacket UDP, dispatch version, select map by community/user, answer GET/GETNEXT/GETBULK/SET.

## Scope
- Admission CIDR + rate
- Community isolation
- SET writes overlay hook (store provided by APP or a thin overlay type)
- Management-off still answers
- v1 GetBulk dropped

## Tests
snmpget/walk/set v1 and v2c; isolation; unknown community silent drop; ready independent of HTTP.

## Acceptance
`snmpwalk -v2c -c public 127.0.0.1:1161 10.20.0.3.2.1.1` lists the public map only.
