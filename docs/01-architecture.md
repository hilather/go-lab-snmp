# 01 — Architecture

Status: Proposed
Owners: Architecture, Data Plane
Last reviewed: 2026-09-04

## Problem

QA needs an SNMP endpoint that is version-accurate, identity-accurate, and map-accurate. One tester walks `public` and sees a switch ifTable. Another walks `vendor` and sees a different enterprise tree. A third binds v3 user `alice`. A fourth sends a linkDown trap and waits for it on MCP. The lab host must not run net-snmp.

## Naming

| Kind | Value |
|---|---|
| Product | LabSNMP |
| Repository | `github.com/hilather/go-lab-snmp` |
| Go module | `github.com/hilather/go-lab-snmp` |
| Binary | `labsnmp` |
| Image | `ghcr.io/hilather/labsnmp` |
| Container user | `65532:65532` |
| Config schema | `labsnmp.dev/v1alpha1` |
| Kind | `LabSNMP` |
| Native REST | `/v1` |
| MCP | `POST /mcp` |
| UI | `/` when `spec.ui.enabled` |
| Agent bind | container `:161` (local escape `:1161`) |
| Trap bind | container `:162` (local escape `:1162`) |
| Management | flag default **off**; image CMD `:8088` |
| Host publish | `10161/udp`, `10162/udp`, `18161/tcp` |
| Session cookie | `labsnmp_session` |
| CSRF header | `X-LabSNMP-CSRF` |
| labinfo id | `labsnmp` |

## Invariants

1. **Two planes, one process.** Agent and trap goroutines never import control/web/http.
2. **Never forward, never originate.** No Dial. INFORM ack is `WriteTo` source.
3. **Never write the bootstrap file.**
4. **YAML KnownFields fail-closed.** camelCase wire names.
5. **Secrets file-ref.** v3 keys never inline. Management token ≥32 bytes.
6. **Data plane keeps accepting if management is off or slow.**
7. **Ready** = enabled agent and/or trap listeners bound + snapshot installed + (management bound OR `--management-listen=off`).
8. **Community/user → exactly one named map.** Split-horizon is two maps.
9. **SET overlay is ephemeral.** Reset drops it.
10. **DTLS / TCP SNMP `enabled: true` rejected in 1.0.**

## Process model

```text
SUT UDP/161 --> snmpagent --> snmpwire.Decode --> usm/community
                     |                |
                     |                v
                     |          view + mibtree.Get/GetNext/GetBulk/Set
                     |                |
                     |                v
                     |          snmpwire.Encode Response
                     |
SUT UDP/162 --> snmpsink --> decode --> store.Insert
                     |                    (INFORM -> WriteTo source)
                     |
              atomic.Pointer[Snapshot]
                     ^
              compiler.Compile(YAML + SET overlay)
```

## Package layout

| Package | Role |
|---|---|
| `cmd/labsnmp` | CLI only |
| `internal/snmpwire` | BER + SNMPv1/v2c/v3 message + PDUs |
| `internal/usm` | v3 USM auth/priv, engine ID, time window |
| `internal/mibtree` | lexicographic OID tree per map |
| `internal/snmpagent` | UDP 161 listen, dispatch |
| `internal/snmpsink` | UDP 162 listen, INFORM ack, insert |
| `internal/store` | trap ring + SET overlay |
| `internal/compiler` | Normalize + Validate + compile Snapshot |
| `internal/snapshot` | immutable Snapshot + atomic Store |
| `internal/config` | KnownFields, duration, bytesize, oid |
| `internal/model` | Spec/Community/User/Map/Object/Trap — no wire types |
| `internal/domainerr` | catalog codes |
| `internal/app` | plan/apply/reset/preview/query/traps |
| `internal/audit` | mutation ring |
| `internal/auth` | bearer + cookie CSRF |
| `internal/capabilities` | frozen REST↔MCP table |
| `internal/control/rest` | `/v1` adapter; must not import web |
| `internal/control/mcp` | `/mcp` adapter |
| `internal/web` | go:embed SPA |
| `internal/observability` | slog JSON, OpenMetrics |
| `internal/snmptest` | test client; not linked from cmd except tests |
| `internal/testutil` | fake clock |
| `internal/buildinfo` | version, MCP protocol constant |

## Import fence

- wire/agent/sink/mibtree/usm/store must not import control, web, net/http
- production rest must not import web
- forbidden production imports: `github.com/gosnmp/gosnmp`, `github.com/sleepinggenius2/gosmi`, `github.com/k-sone/snmpgo`
- forbidden Dial; forbidden exec basenames `snmpd`, `snmptrapd`, `snmpget`, `snmpwalk`, `snmptrap`, `snmpinform`
- INFORM `WriteTo` is allowed and tested

## Listen

- `net.ListenPacket("udp", addr)` for agent and sink
- Client IP `netip.Addr.Unmap()` before CIDR admission
- UID 65532 vs :161/:162 needs `CAP_NET_BIND_SERVICE` on integrator compose
- Local tests bind `:1161` / `:1162` with cap_drop ALL
- `labsnmp serve --config --snmp-listen` binds the agent. `--trap-listen` empty uses YAML `spec.listeners.traps.address` when `traps.enabled`; `off` disables. `--management-listen` defaults **off**; the data plane still answers. Ready includes the trap listener when it is enabled.
