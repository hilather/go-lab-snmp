# ADR 0006 — Pin MCP protocol versions

Status: Accepted
Date: 2026-09-04
Related: D11, D17

Official `github.com/modelcontextprotocol/go-sdk v1.7.0`, protocol
`2026-07-28`, Streamable HTTP `Stateless: true`. Tools `snmp_*`.
Resources `labsnmp://`. `allowLegacyClients` default false; lab overlay
true. Other protocol revisions are rejected unless that overlay is set.
