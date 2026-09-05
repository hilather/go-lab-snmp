# 07 — MCP API

Status: Proposed
Owners: Control Plane
Last reviewed: 2026-09-05
Related ADRs: 0004, 0006

Official SDK `github.com/modelcontextprotocol/go-sdk` **v1.7.0**, protocol
**`2026-07-28`**, Streamable HTTP `POST /mcp` with `Stateless: true`.
`allowLegacyClients` defaults false; lab overlays may set true.

Tools are `snmp_*`. Resources are `labsnmp://…`. Bearer-only.
MCP must not HTTP-call REST. `labsnmp mcp-stdio` requires `--config`
and `--token-file`.

Tools and resources: `docs/05-control-plane-and-parity.md`.
Pin protocol version; reject others unless `allowLegacyClients` is true.
