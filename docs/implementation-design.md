# LabSNMP implementation design

> **Living contract.** ADRs, `AGENTS.md`, and numbered `docs/00`–`13`
> win over this summary. Edit this root copy, not the design pack.
> CLI listen flags are `--snmp-listen`, `--trap-listen`, and
> `--management-listen`. Packages are `internal/mibtree` and
> `internal/snmpagent` (not `mib` / `snmpserver`). Control-plane
> implementation order is CFG → APP → API → SEC → MCP; D8 is the
> adapter subsequence REST → Auth → MCP.

**Status:** accepted for implementation  
**Date:** 2026-09-04  
**Target:** https://github.com/hilather/go-lab-snmp  
**API group:** `labsnmp.dev/v1alpha1`  
**License:** Apache-2.0  

## Overview

LabSNMP is a single-process Go lab appliance. SUTs speak SNMPv1/v2c/v3 over UDP/161 against YAML OID maps bound per community and per USM user. UDP/162 is a receive-only trap/inform sink. Never wrap net-snmp. Never forward.

Closest siblings: LabNTP (first-party UDP responder), LabMail (receive-only store), LabLDAP (multi-identity), LabSyslog (pack format).

## Goals (1.0)

- Agent: Get / GetNext / GetBulk / Set
- Versions: v1, v2c, v3 USM (MD5 / SHA-1 / SHA-256 + DES / AES-128)
- Per-community and per-user named maps (split-horizon)
- SET overlay + control-plane `snmp_oid_set`
- Trap/inform capture + wait
- YAML GitOps, REST `/v1`, MCP `2026-07-28`, operator UI
- Scratch image UID 65532
- Examples BOM for mcp-integration-lab

## Non-goals (1.0)

- net-snmp / AgentX / gosnmp-as-engine
- SMIv2 compiler
- SNMP over TCP / DTLS
- Trap originator or forwarder
- Manager that walks external agents
- SHA-384/512, AES-192/256
- Product logic in mcp-integration-lab

## Decisions

| ID | Decision |
|---|---|
| D1 | Module `github.com/hilather/go-lab-snmp` |
| D2 | First-party `snmpwire`; no gosnmp types in model |
| D3 | Two planes, one process |
| D4 | Never forward / never originate (ADR 0007) |
| D5 | YAML KnownFields; camelCase; kebab reject |
| D6 | `spec.auth` bearer-only; `spec.management.auth` unknown |
| D7 | MCP `2026-07-28`; tools `snmp_*`; resources `labsnmp://` |
| D8 | Control-plane order CFG → APP → API → SEC → MCP; adapter subsequence REST → Auth → MCP |
| D9 | Community/user → exactly one map |
| D10 | SET overlay; reset drops it |
| D11 | INFORM ack is WriteTo, not Dial |
| D12 | TCP/DTLS enable rejected in 1.0 |
| D13 | Host residual 10161/10162; native 161/162 |
| D14 | Local escape `:1161` / `:1162` |
| D15 | labinfo id `labsnmp` from day one |
| D16 | UI required for 1.0 GA |
| D17 | `allowLegacyClients` default false; lab overlay true |
| D18 | Hand-rolled OpenMetrics |
| D19 | Official MCP SDK only on the adapter |
| D20 | `valueFrom: processUptime` is the only dynamic source |
| D21 | Community inline XOR `communityFile` |
| D22 | No userland-proxy readiness gate (identity is community/user) |
| D23 | Placeholder Make targets fail closed |
| D24 | Integrator pin LAST |
| D25 | Go 1.26, Apache-2.0, image `ghcr.io/hilather/labsnmp` |
| D26 | Cookie `labsnmp_session`; CSRF `X-LabSNMP-CSRF` |
| D27 | Ready = enabled listeners bound + snapshot + (mgmt bound or off) |
| D28 | Unauth traps dropped by default |

## Package map

```
cmd/labsnmp
internal/{model,config,compiler,snapshot,mibtree,snmpwire,usm,snmpagent,
          snmpsink,store,app,capabilities,control/rest,control/mcp,auth,
          audit,domainerr,observability,buildinfo,web,testutil,snmptest}
api/{jsonschema,openapi,mcp,capabilities,metrics,errors}
web testdata examples docs tasks scripts
```

## CLI

```
labsnmp version
labsnmp validate --config FILE
labsnmp canonicalize --config FILE [--format yaml|json]
labsnmp serve --config FILE [--snmp-listen ADDR|off] [--trap-listen ADDR|off] [--management-listen ADDR|off]
labsnmp healthcheck --url URL
labsnmp mcp-stdio --config FILE --token-file FILE
```

## PR plan

See `tasks/00-program-board.md`. WIRE-001 is the critical path.
