# ADR 0015 — Community file refs

Status: Accepted
Date: 2026-09-04

## Context

Numbered docs disagreed on how v1/v2c community strings are stored:

- `AGENTS.md` requires file refs (`communityFile`)
- `docs/02` allowed inline `community:` XOR `communityFile`
- `docs/04` treated `name` as the wire string with optional `secretFile`

Hilather products keep secrets out of bootstrap YAML. SNMPv1/v2c
communities are cleartext **on the wire** (the protocol has no
confidentiality) but still must not be inlined in GitOps YAML.

## Decision

- `communities[].name` is a required unique DNS-label **row id**
  (REST/MCP/UI). It is not the wire community string.
- `communities[].communityFile` is required. The wire octet string is
  the trimmed file contents. Wire strings must be unique after
  resolution.
- Inline `community:`, using `name` as the wire string, or
  `secretFile` on a community row is an unknown field or validate
  error.
- Management tokens stay `secretFile` only, ≥32 bytes. USM
  `auth.secretFile` / `priv.secretFile` stay file-ref only, ≥8 bytes.
- Missing or short secret files fail **validate**.

## Consequences

- Testdata and integrator compose mount community files (for example
  `testdata/secrets/snmp-public`).
- GET state, UI, info logs, and metric labels never include secret
  **bytes**. Paths may appear.
- Changing this invariant later requires another ADR.
