# Program board — LabSNMP 1.0

Status: Proposed
Last reviewed: 2026-09-04

Agents implement one work package per change. Control-plane order is
CFG → APP → API → SEC → MCP. Data plane proceeds after WIRE.

## Work packages

| Order | Task | ID | Depends | Milestone |
| ---: | --- | --- | --- | --- |
| 1 | Repository foundation | FND-001 | — | M0 |
| 2 | Domain + fail-closed YAML | CFG-001 | FND-001 | M0 |
| 3 | First-party snmpwire | WIRE-001 | CFG-001 | M1 |
| 4 | OID map tree GETNEXT | MAP-001 | CFG-001 | M1 |
| 5 | v3 USM bounded | USM-001 | WIRE-001 | M1 |
| 6 | UDP 161 agent | AGENT-001 | WIRE-001, MAP-001, USM-001 | M1 |
| 7 | UDP 162 trap sink | TRAP-001 | WIRE-001 | M1 |
| 8 | Snapshot plan/apply/reset + overlay | APP-001 | CFG-001, MAP-001, TRAP-001 | M2 |
| 9 | REST /v1 | API-001 | APP-001 | M2 |
| 10 | Bearer + CSRF + audit | SEC-001 | API-001 | M2 |
| 11 | MCP + parity | MCP-001 | API-001, SEC-001 | M2 |
| 12 | Observability | OBS-001 | AGENT-001, API-001 | M3 |
| 13 | CLI + scratch image | DEP-001 | AGENT-001, TRAP-001, API-001 | M3 |
| 14 | Operator SPA | UI-001 | API-001, SEC-001 | M4 |
| 15 | Integration-lab BOM | SWAP-001 | MCP-001, SEC-001, DEP-001 | M4 |
| 16 | GA hardening | GA-001 | 1–15 | M5 |
| — | DTLS / TCP SNMP | TLS-001 | DEP-001 | v1.1 |

## Parallelization

- WIRE-001 is the critical path. Do not invent gosnmp types while it is open.
- MAP-001 can proceed from CFG-001 in parallel with WIRE.
- USM-001 after WIRE.
- AGENT-001 needs WIRE + MAP + USM.
- TRAP-001 after WIRE; can parallel AGENT.
- APP-001 after CFG + MAP + TRAP store.
- API after APP; SEC after API; MCP after API+SEC.
- UI required for 1.0 GA; rc.1 may be API-complete.
- SWAP-001 is docs+examples in this repo. Integrator PR is out of band.

## Milestones

- **M0** FND+CFG, ADRs accepted, fixtures exist.
- **M1** snmpget/snmpwalk/snmpset/snmptrap against localhost with management off.
- **M2** plan/apply/reset + wait + parity.
- **M3** hardened image + compose.smoke.
- **M4** UI + BOM.
- **M5** GA tag-gate.

## Frozen decisions

- Q1: labinfo id and compose name are `labsnmp` from day one.
- Q2: agent + trap sink both 1.0.
- Q3: v1+v2c+v3 USM 1.0, DTLS v1.1.
- Q4: per-community and per-user maps.
- Q5: SET is overlay, not apply.
- Q6: INFORM WriteTo is allowed; Dial is not.
