# Family evaluation — mcp-integration-lab and LabSNMP

**Last reviewed:** 2026-09-04  
**Integrator:** https://github.com/hilather/mcp-integration-lab  
**Target:** https://github.com/hilather/go-lab-snmp (empty)

`mcp-integration-lab` is a docker-compose laboratory that publishes real network protocols on the host and drives them from one MCP gateway (MCPJungle). Configuration lives in `profiles/<name>/`. Runtime state is ephemeral.

LabSNMP fills the SNMP hole the same way LabMail filled SMTP and LabSyslog fills syslog: a first-party appliance with YAML desired state, REST + MCP + UI, vendored last.

## Lab members

| Project | Pin (lab today) | Role | Wire | MCP prefix | Default profile ports | What LabSNMP copies | What it leaves |
|---|---|---|---|---|---|---|---|
| MCPJungle | 0.4.6 | MCP gateway | HTTP `/mcp` | n/a | 8080 | registration JSON, `allowLegacyClients`, filename = name | no product logic |
| LabDNS `go-lab-dns` | v1.3.0 | Auth DNS | UDP/TCP 53 | `dns_*` | 10053 residual, 18080 | numbered docs, ADRs, program board, KnownFields, snapshot | chaos, forwarding |
| LabLDAP `go-lab-ldap-mcp` | v0.5.0 | Directory | LDAP 389/636 | `ldap_*` | 3389/3636 residual, 8443 | multi-identity (users/bind), REST+MCP+UI triad | 389ds oracle |
| TacLab `go-lab-tacacs-mcp` | v1.5.0 | TACACS+ / RADIUS | 49/300, 1812/1813 | `tac_*` | native AAA ports, 18049 | native IANA dests, shared-secret file refs | AAA state machines |
| LabMail `go-lab-maildev` | v1.0.0-rc.4 | SMTP sink | SMTP 25 | `mail_*` | 1025 residual, 1080 | trap-sink analog: receive-only, reserved keys, wait, wipe | MIME, Basic, `/email` |
| LabMITM `go-lab-mitmproxy` | v1.6.0 | HTTP intercept | forward proxy | `mitm_*` | 18888, 18088 | capture list + raw view | CONNECT / CA |
| LabNTP `go-lab-ntp` | v1.0.0-rc.2 | Virtual clocks | NTP 123 UDP | `ntp_*` | 10123, 18123 | **protocol analog**: first-party wire, UDP independence, NET_BIND_SERVICE, `spec.auth` | clock math |
| LabSSO `go-lab-sso` | v1.0.0-rc.1 | IdP | HTTPS 443 | `sso_*` | dest-443, 18443 | dest-vs-escape port docs | OIDC/SAML |
| LabSyslog `go-lab-syslog` | design only | Syslog sink | 514 UDP/TCP | `syslog_*` | 10514 residual, 18514 | pack format, trap-store shape, unmatched=capture for sink | syslog codecs |
| ratarmount-rs | v0.1.28 | NFSv3 | 2049 | none | 20490 | ephemeral overlay idea | Rust |
| labinfo | in-tree | Service directory | HTTP | endpoints/connections | 18090 | connection block required | integrator |
| labgraph | in-tree | Scenarios | HTTP | plan/apply | 18091 | later fixture packs (walk-ifTable, set-ifAdmin, trap-flood) | not 1.0 appliance |
| go-lab-netconf | empty | future | — | — | — | same pack later | not this project |

## Why this product exists

The lab can publish DNS, LDAP, TACACS+, RADIUS, SMTP, HTTP intercept, NTP, and SSO. Network devices and NMSes under test still speak SNMP. Today there is no appliance that:

- answers `snmpwalk -v2c -c public` with a deterministic ifTable
- presents a *different* tree on community `vendor` vs `public` (split-horizon)
- accepts a v3 user `alice` with SHA-256/AES
- captures a cold-start trap and lets an agent `snmp_traps_wait`

That is LabSNMP.

## Methodologies LabSNMP must follow

- Go 1.26, Apache-2.0, one binary, two planes
- YAML `*.dev/v1alpha1`, KnownFields, camelCase tags
- Bootstrap read-only; snapshot atomic; reset rereads
- REST `/v1` + MCP `2026-07-28` + UI `/`
- File-backed bearer ≥32 bytes at `spec.auth`
- UID 65532, scratch, cap_drop ALL
- First-party wire codec
- Integrator pin LAST
- Docs numbered 01–13 + ADRs + tasks waves
- Native IANA dest documented; residual high host port as default profile

## Port policy

| Plane | IANA | Container | Default profile host | Escape |
|---|---|---|---|---|
| Agent | 161/udp | `:161/udp` | 10161/udp | `LABSNMP_AGENT_PORT=161` |
| Traps | 162/udp | `:162/udp` | 10162/udp | `LABSNMP_TRAP_PORT=162` |
| Management | n/a | `:8088/tcp` | 18161/tcp | `LABSNMP_MGMT_PORT` |
| SNMP/TLS | 10161-ish / RFC 6353 | not in 1.0 | — | v1.1 |

161 is often held by `snmpd`. 10161 is residual-as-default, not the design.

## Integrator later (SWAP-001)

See `docs/13-integration-lab.md`. No product logic in `mcplab`.
