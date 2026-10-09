# Agent guide — LabSNMP

This repo is a laboratory SNMP agent simulator with a receive-only
trap/inform sink. It is a sibling of LabNTP (responder) and LabMail
(sink) and will be vendored by `mcp-integration-lab`.

Read before modifying code:

1. `docs/00-family-evaluation.md`
2. `docs/01-architecture.md`
3. `docs/02-snmp-semantics.md`
4. `docs/03-mib-and-trap-store.md`
5. `docs/04-state-and-configuration.md`
6. `docs/05-control-plane-and-parity.md`
7. Every ADR relevant to the changed area

Do not invent paths, types, capability IDs, or USM algorithms.
Changing an invariant requires an ADR first.

## Frozen identity

| Field | Value |
|---|---|
| Product | LabSNMP |
| Binary | `labsnmp` |
| Module | `github.com/hilather/go-lab-snmp` |
| Image | `ghcr.io/hilather/labsnmp` |
| Schema | `labsnmp.dev/v1alpha1` |
| Kind | `LabSNMP` |
| Cookie | `labsnmp_session` |
| CSRF | `X-LabSNMP-CSRF` |
| User | `65532:65532` |
| Config | `/etc/labsnmp/config.yaml` |
| Token | `/run/secrets/labsnmp-token` |
| labinfo id | `labsnmp` |
| MCP tools | `snmp_*` |
| Resources | `labsnmp://…` |
| MCP protocol | `2026-07-28` |
| Go | 1.26 language, toolchain go1.26.9 (ADR 0017) |
| MCP SDK | `github.com/modelcontextprotocol/go-sdk v1.7.0` |
| License | Apache-2.0 |

## Ground rules

1. **Two planes, one process.** Agent UDP 161 and trap UDP 162 keep
   working if management is off or slow. `internal/snmpwire`,
   `internal/mibtree`, `internal/usm`, `internal/snmpagent`,
   `internal/snmpsink`, `internal/store` MUST NOT import
   `internal/control`, `internal/web`, or `net/http`.
2. **No outbound SNMP.** Production those packages plus `internal/app`
   MUST NOT `Dial` / `DialTimeout` / `Dialer.Dial`. INFORM ack is
   `WriteTo` on UDP or `Write`/`WriteTCP` on the accepted connection.
   No trap originator. No manager CLI.
3. **Never rewrite bootstrap YAML.** Reset rereads it, clears the SET
   overlay, and wipes the trap store.
4. **KnownFields(true).** camelCase YAML. kebab aliases reject.
   Auth is `spec.auth` (LabNTP). `spec.management.auth` is unknown.
   `auth.mode` is `bearer` only.
5. **Secrets are file refs.** Management tokens ≥32 bytes.
   Community strings live in `communityFile`. USM keys live in
   `auth.secretFile` / `priv.secretFile`.
6. **REST and MCP are adapters.** One `app.Service`. They must not
   call each other. Order CFG → APP → API → SEC → MCP.
7. **First-party codec.** Do not import gosnmp, gosmi, net-snmp cgo.
   Do not exec `snmpd`, `snmptrapd`, `snmpget`, `snmpwalk`, `snmptrap`
   in production (allowed in `_test.go`).
8. **v3 algorithms are an allowlist.** MD5, SHA-1, SHA-256, DES,
   AES-128. Anything else `usm_alg_unsupported`.
9. **SET is an overlay.** Not an apply verb. REST `oids:set` is the
   same overlay. Reset restores bootstrap values.
10. **No SMIv2 compiler in 1.0.** Explicit YAML maps.
11. **DTLS/TCP SNMP is schema-legal in 1.1.** `enabled: true`
    validates under per-listener TCP constraints and DTLS file-ref
    certs. TLSTM/TSM is not implemented. Do not add
    `spec.listeners.tls`.
12. **No Prometheus client.** Hand-rolled OpenMetrics.
13. **Docs ship with the change.** CI failures are hardened.
14. **Identity for views is community string or v3 user**, not client
    IP. Do not copy LabNTP unmatched-drop or per-IP views.

## Reserved keys

Normalized (strip `-` `_`, lower-case) prefixes:
`forward*`, `relay*`, `remote*`, `destination*`, `trapdest*`,
`notifytarget*`, `proxy*`, `manager*`, `agentx*`, `smux*`,
`netsnmp*`, `snmpd*`.

## Allowed 1.0 direct deps

- `gopkg.in/yaml.v3`
- `github.com/modelcontextprotocol/go-sdk v1.7.0`
- `github.com/oklog/ulid/v2`
- `github.com/pion/dtls/v3` (v3.1.8 or newer patch `govulncheck`
  accepts; inbound `ListenWithOptions` only)

Stdlib crypto for USM. New deps need a PR justification and
Apache-2.0 license check.

## Capability IDs

Frozen in `docs/05-control-plane-and-parity.md`. Do not invent a
second name. Filters/maps mutate through `changes:plan`/`apply`
except overlay `oids:set`.

## Required completion commands

```
make format lint generate verify-generated test test-race
make test-fuzz-smoke test-parity test-config-compat test-docs
make test-container security-scan test-changelog web-test web-build
```

Missing targets exit 1.

## Locked tests

- KnownFields unknown-field reject
- reserved-key reject
- `usm_alg_unsupported` for sha384/aes256
- `spec.management.auth` unknown
- token short / missing file
- Dial AST on production packages
- forbidden module AST
- GETNEXT order
- SET overlay cleared by reset
- INFORM WriteTo (not Dial)
- unknown community silent drop
