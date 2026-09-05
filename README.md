# LabSNMP

**One agent. A different MIB for every community.**

Answer GET/WALK/SET from YAML. Capture traps. Do it from REST or
MCP — without running snmpd, and without one tester trampling
another tester's view.

This is laboratory software. It is not a production SNMP agent.

| | |
|---|---|
| Binary | `labsnmp` |
| Module | `github.com/hilather/go-lab-snmp` |
| Image | `ghcr.io/hilather/labsnmp` |
| Config | `labsnmp.dev/v1alpha1` · kind `LabSNMP` |
| Agent | UDP SNMPv1/v2c/v3 · container `:161` · host residual **10161** |
| Traps | UDP sink · container `:162` · host residual **10162** |
| Control | REST `/v1` · MCP `/mcp` · UI `/` · host **18161** |

## Status

Control plane through SEC-001 plus the operator SPA (UI-001). Mira
checklist signed off for 1.0.0. Remaining waves start from
`tasks/00-program-board.md`. Read `START-HERE.md`, then `AGENTS.md`.

## What 1.0 will do

- SNMPv1 + v2c communities with **per-community OID maps**
- SNMPv3 USM users (MD5/SHA-1/SHA-256 + DES/AES-128) with **per-user maps**
- GET, GETNEXT, GETBULK, SET (writable leaves → ephemeral overlay)
- Trap/Inform sink with wait/list (never forward, never originate)
- YAML desired state, REST + MCP parity, operator UI

## What 1.0 will not do

- Wrap net-snmp / AgentX
- Compile SMIv2 MIBs
- Walk or SET a remote agent
- SNMP over TCP or DTLS
