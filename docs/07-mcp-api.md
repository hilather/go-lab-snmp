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
and `--token-file`. mcp-stdio binds the process to that token id. Each
tool call re-reads the id from the live verifier. A reset that demotes
the id drops `snmp.admin` on the next call. Removing the id denies
every scoped tool. HTTP MCP with a bearer header still authenticates
that header.

Tools and resources: `docs/05-control-plane-and-parity.md`.
Pin protocol version; reject others unless `allowLegacyClients` is true.
