# 07 — MCP API

Status: Proposed
Owners: Control Plane
Last reviewed: 2026-09-04

Protocol `2026-07-28`. Streamable HTTP `POST /mcp`. Stateless.
SDK v1.7.0. Bearer only. `labsnmp mcp-stdio --config --token-file`.

Tools and resources: `docs/05-control-plane-and-parity.md`.
MCP must not HTTP-call REST. `allowLegacyClients` default false.
