# Program board — LabSNMP

Status: 1.0 shipped (`v1.0.0`). v1.1 residual increment in progress.
Last reviewed: 2026-09-05

Agents implement one work package per change. Control-plane order is
CFG → APP → API → SEC → MCP. Data plane proceeds after WIRE.
v1.1: CFG → APP → AGENT/TRAP → DEP. UI after status names exist.

## 1.0 work packages (shipped)

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

TLS-001 is **no longer deferred**. v1.1 work is the table below
(`tasks/v1.1-*.md`). `tasks/wave-17-dtls-v1.1.md` points here.

## v1.1 work packages

| Order | Task | ID | Depends | Milestone |
| ---: | --- | --- | --- | --- |
| 1 | v1.1 design, ADR 0016, board | FND-110 | — | v1.1 |
| 2 | INFORM InformAck-before-WriteTo | BUG-110 | — | v1.1 |
| 3 | UDP SyncDataPlane (Reset rebind) | REBIND-110 | — | v1.1 |
| 4 | TCP/DTLS listener schema | CFG-110 | FND-110 | v1.1 |
| 5 | RFC 3430 BER TCP framing | WIRE-110 | FND-110 | v1.1 |
| 6 | Snapshot, Ready, Status listeners | APP-110 | CFG-110 | v1.1 |
| 7 | TCP + DTLS agent | AGENT-110 | CFG-110, WIRE-110, APP-110 | v1.1 |
| 8 | TCP + DTLS trap/inform | TRAP-110 | BUG-110, WIRE-110, APP-110, AGENT-110 | v1.1 |
| 9 | Serve flags, EXPOSE | DEP-110 | REBIND-110, AGENT-110, TRAP-110 | v1.1 |
| 10 | Status/Overview TCP/DTLS rows | UI-110 | APP-110 | v1.1 |
| 11 | linux/arm64 GHCR | ARM-110 | — | v1.1 |
| 12 | Living docs mop-up | DOCS-110 | CFG-110, DEP-110 | v1.1 |
| 13 | Overlay stays off | SWAP-110 | DOCS-110 | v1.1 |
| 14 | v1.1.0 release notes | GA-110 | 1–13 | v1.1 |

Authority: `IMPLEMENTATION-DESIGN-v1.1.md`, ADR 0016.

## Parallelization

- WIRE-001 is the 1.0 critical path (shipped). Do not invent gosnmp types.
- SWAP-001 is docs+examples in this repo. Integrator PR is out of band.
- v1.1: BUG-110, REBIND-110, WIRE-110, and ARM-110 parallelize with FND-110.
- CFG-110 after FND-110 (ADR first). Do not flip AGENTS §11 / checkdocs
  / validate before CFG-110.
- APP-110 after CFG. AGENT-110 after CFG+WIRE+APP; pion pin +
  `make security-scan` is the AGENT-110 merge gate. Do not add pion
  before AGENT-110.
- TRAP-110 after BUG+WIRE+APP+AGENT (pion already in go.mod).
- DEP-110 after REBIND+AGENT+TRAP. UI-110 after APP (listener names).
- Integrator pin remains out of band. GA-110 last; do not git tag in
  that PR.

## Milestones

- **M0** FND+CFG, ADRs accepted, fixtures exist.
- **M1** snmpget/snmpwalk/snmpset/snmptrap against localhost with management off.
- **M2** plan/apply/reset + wait + parity.
- **M3** hardened image + compose.smoke.
- **M4** UI + BOM.
- **M5** GA tag-gate (`v1.0.0` shipped).
- **v1.1** TLS-001 (RFC 3430 TCP + DTLS 1.2 record layer), INFORM race,
  Reset rebind, linux/arm64. Tag `v1.1.0`.

## Frozen decisions

- Q1: labinfo id and compose name are `labsnmp` from day one.
- Q2: agent + trap sink both 1.0.
- Q3: v1+v2c+v3 USM 1.0; TCP/DTLS v1.1 (TLS-001 no longer deferred).
- Q4: per-community and per-user maps.
- Q5: SET is overlay, not apply.
- Q6: INFORM WriteTo is allowed; Dial is not.
- TCP = RFC 3430 BER-length framing (not a 32-bit prefix). DTLS = DTLS
  1.2 record layer on 10161/10162; TLSTM/TSM not implemented (ADR 0016).
