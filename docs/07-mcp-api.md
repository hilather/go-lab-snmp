# 07 — MCP API

Status: Proposed
Owners: Control Plane
Last reviewed: 2026-10-07
Related ADRs: 0004, 0006

Official SDK `github.com/modelcontextprotocol/go-sdk` **v1.7.0**, protocol
**`2026-07-28`**, Streamable HTTP `POST /mcp` with `Stateless: true`.
`allowLegacyClients` defaults false; lab overlays may set true.

Tools are `snmp_*`. Resources are `labsnmp://…`. Bearer-only.
MCP must not HTTP-call REST. `labsnmp mcp-stdio` requires `--config`
and `--token-file`. mcp-stdio re-authenticates that startup secret on
each tool call. The process acts as whatever principal the secret
authenticates as now. A same-id secret rotation revokes the stdio
process. Demoting that principal drops `snmp.admin` on the next call.
Removing the secret denies every scoped tool. HTTP MCP with a bearer
header still authenticates that header.

Tools and resources: `docs/05-control-plane-and-parity.md`.
Pin protocol version; reject others unless `allowLegacyClients` is true.
