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
| Agent | UDP/TCP SNMPv1/v2c/v3 · DTLS 1.2 record layer · container `:161` · host residual **10161** |
| Traps | UDP/TCP sink · DTLS record layer · container `:162` · host residual **10162** |
| Control | REST `/v1` · MCP `/mcp` · UI `/` · host **18161** |

## Status

**1.0.0** shipped. v1.1 residual increment: TLS-001 (RFC 3430 TCP +
DTLS 1.2 record layer) is no longer deferred; TLSTM/TSM is not
implemented. Scratch image UID `65532:65532`. `make test-container`
smokes `:1161`/`:1162` with `cap_drop: ALL`. Operator SPA Mira
checklist is signed off. Tag-gate is `docs/releases/v1.0.0.md`; do
not git tag unless required CI is green. Read `START-HERE.md`, then
`AGENTS.md`.

## What 1.0 will do

- SNMPv1 + v2c communities with **per-community OID maps**
- SNMPv3 USM users (MD5/SHA-1/SHA-256 + DES/AES-128) with **per-user maps**
- GET, GETNEXT, GETBULK, SET (writable leaves → ephemeral overlay)
- Trap/Inform sink with wait/list (never forward, never originate)
- YAML desired state, REST + MCP parity, operator UI

## What 1.1 adds

- RFC 3430 SNMP over TCP (BER-length framing)
- DTLS 1.2 record layer on IANA 10161/10162 (not TLSTM/TSM)

## What 1.0 will not do

- Wrap net-snmp / AgentX
- Compile SMIv2 MIBs
- Walk or SET a remote agent
- RFC 6353 TLSTM/TSM or TLS-over-TCP
