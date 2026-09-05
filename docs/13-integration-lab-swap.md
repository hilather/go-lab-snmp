# 13 — Integration with MCP Integration Lab

Status: Proposed
Owners: Integration
Last reviewed: 2026-09-05

Integrator change is LAST and orchestration-only. This document is the
BOM. Product logic never moves into `mcplab`. There is **no** SNMP
service in the lab today — the integrator PR (out of band) adds it by
copying the files in `examples/`. **Do not implement
`internal/lab/vendor.go` in this repo.** No codec, MIB, or USM logic
in `internal/lab`.

## Overlay files in this repo

Copy these into `mcp-integration-lab` at the paths in the BOM. Do not
invent a second schema. Do not recopy `testdata/config/valid/full.yaml`.

| This repo | Lab destination | Role |
|---|---|---|
| [examples/labsnmp.yaml](../examples/labsnmp.yaml) | `profiles/default/labsnmp/bootstrap.yaml` | Lab overlay. Maps `public-if` / `private-if`, user `alice` authPriv SHA-256/AES-128, `allowLegacyClients: true`, lab CIDRs. Secret paths `/run/secrets/…`. Not the DEP-001 compose-smoke file. |
| [examples/mcpjungle/servers/labsnmp.json](../examples/mcpjungle/servers/labsnmp.json) | `profiles/default/mcpjungle/servers/labsnmp.json` | Filename must match JSON `name`. URL is `http://labsnmp:8088/mcp`. |
| [examples/mcpjungle/groups/integration.json](../examples/mcpjungle/groups/integration.json) | `profiles/default/mcpjungle/groups/integration.json` | **Append** `"labsnmp"` to `included_servers`. Do not replace the group. |
| [examples/labinfo/services-labsnmp.yaml](../examples/labinfo/services-labsnmp.yaml) | merge into `profiles/default/labinfo/services.yaml` | Catalog id is `labsnmp`. Must include `urls` + `connection`. |
| [examples/compose.smoke.yaml](../examples/compose.smoke.yaml) | container-local smoke only | DEP-001 smoke on `:1161`/`:1162` with `cap_drop: ALL`. Do not mount `examples/labsnmp.yaml` as the smoke config unless the smoke compose mints and mounts the secret files at 0o644. |

Acceptance twin in this repo: `TestLabOverlayExample` /
`TestLabMCPJungleExamples` / `TestLabinfoSnippetKeepsCatalogID` in
`internal/config/example_overlay_test.go`.

## Naming

| Kind | Value |
|---|---|
| Compose service | `labsnmp` |
| labinfo id | `labsnmp` |
| Jungle name / file | `labsnmp` / `labsnmp.json` |
| Token | `secrets/labsnmp-token` `0o644` |
| Config mount | `/etc/labsnmp/config.yaml` |
| Image local | `labsnmp:local` from `./third_party/go-lab-snmp` |

Do not reuse a `snmpd` compose name.

## Vendor pin (integrator PR, out of band)

`internal/lab/vendor.go` in **mcp-integration-lab**, not this repo:

```
URL:  https://github.com/hilather/go-lab-snmp
Dest: third_party/go-lab-snmp
Ref:  v1.0.0
```

The integrator pin is out of band. Ref stays the last GA tag until
v1.1.0 is tagged. Do not edit `third_party/` in place.

## Locked ports

| Variable | Default | Notes |
|---|---|---|
| `LABSNMP_AGENT_PORT` | `10161` | Residual host publish; container dest is `:161/udp` |
| `LABSNMP_TRAP_PORT` | `10162` | Residual host publish; container dest is `:162/udp` |
| `LABSNMP_REST_PORT` | `18161` | Management HTTP (REST + MCP + SPA). **Not** `LABSNMP_MGMT_PORT` |

`LABSNMP_MGMT_PORT` (docs/00 family table) is a **rejected alias** —
not YAML, not compose, not labinfo, not profile.env. Do not read it.

IANA dest is 161/162. Residual is the shipped default because snmpd
and snmptrapd commonly hold those ports. Preflight occupancy is
`/proc/net` UDP bound. `EACCES` is not occupied. Error copy names
the fix: stop snmpd/snmptrapd, extra IP for `LAB_PUBLIC_HOST`, or
keep 10161/10162.

Also inject `LABSNMP_*` into the labinfo compose environment.

## Compose (copy LabNTP)

Integrator compose binds IANA `:161` / `:162` inside the container
and restores **only** `cap_add: [NET_BIND_SERVICE]`. Default
`examples/compose.smoke.yaml` stays `:1161`/`:1162` with
`cap_drop: ALL`.

`--management-listen` defaults to `off` on the binary. The lab
command **must** pass `--management-listen=:8088` so healthcheck,
REST, MCP, and the SPA bind.

```yaml
labsnmp:
  image: labsnmp:local
  build: ./third_party/go-lab-snmp
  command: ["serve", "--config=/etc/labsnmp/config.yaml", "--management-listen=:8088"]
  user: "65532:65532"
  read_only: true
  tmpfs: ["/tmp"]
  cap_drop: [ALL]
  cap_add: [NET_BIND_SERVICE]
  security_opt: ["no-new-privileges:true"]
  restart: unless-stopped
  networks: [default]
  ports:
    - "${LABSNMP_AGENT_PORT:-10161}:161/udp"
    - "${LABSNMP_TRAP_PORT:-10162}:162/udp"
    - "${LABSNMP_REST_PORT:-18161}:8088/tcp"
  volumes:
    - ${MCPLAB_PROFILE_DIR:-./profiles/default}/labsnmp/bootstrap.yaml:/etc/labsnmp/config.yaml:ro
    - ./secrets/labsnmp-token:/run/secrets/labsnmp-token:ro
    - ./secrets/snmp-public:/run/secrets/snmp-public:ro
    - ./secrets/snmp-private:/run/secrets/snmp-private:ro
    - ./secrets/snmp-alice-auth:/run/secrets/snmp-alice-auth:ro
    - ./secrets/snmp-alice-priv:/run/secrets/snmp-alice-priv:ro
  healthcheck:
    test: ["CMD", "/labsnmp", "healthcheck", "--url=http://127.0.0.1:8088/v1/health/ready"]
    interval: 5s
    timeout: 3s
    retries: 12
    start_period: 3s
```

`cap_add NET_BIND_SERVICE` is required because the process binds
`:161` and `:162` inside the container even when the host publish is
10161/10162. Docker must pass `NET_BIND_SERVICE` as an ambient
capability to a non-root process (dockerd ≥20.10 with default
seccomp). `no-new-privileges:true` is compatible because the cap is
already in the bounding set at exec.

Host-publish UDP may SNAT via Docker `userland-proxy` so every laptop
hitting `${LAB_PUBLIC_HOST}:10161` appears as one bridge IP (**NAT
collision**). LabSNMP keys views by community/user, not client IP, so
split-horizon still holds.

## profile.env

```
LABSNMP_AGENT_PORT=10161
LABSNMP_TRAP_PORT=10162
LABSNMP_REST_PORT=18161
```

## labinfo

Id `labsnmp`. Must include `urls` + `connection` or labinfo fails
to start. Copy from
[examples/labinfo/services-labsnmp.yaml](../examples/labinfo/services-labsnmp.yaml).

Connection endpoints:

- `snmp-agent` udp `${LAB_PUBLIC_HOST}:${LABSNMP_AGENT_PORT}`
  versions v1/v2c/v3, communities public/private, user alice
- `snmp-trap` udp `${LAB_PUBLIC_HOST}:${LABSNMP_TRAP_PORT}`
- MCP `http://${LAB_PUBLIC_HOST}:${LABSNMP_REST_PORT}/mcp`

Parameters: DTLS record layer on IANA 10161/10162; inner PDU is
community or USM; TLSTM/TSM is not implemented. RFC 6353
TLS-over-TCP is residual. `connection.parameters.tls` is that
capability note; the lab overlay keeps `tcp.enabled` /
`dtls.enabled` false (v1.1 can enable TCP/DTLS with file-ref
certs; this BOM does not). Maps `public-if` / `private-if`,
auth none on v1/v2c data plane, v3 authPriv SHA-256/AES-128.

`stageLabinfoCreds` must copy `secrets/labsnmp-token` (and the
community / alice files) into `secrets/labinfo-creds/` so the catalog
paths resolve.

## Jungle

Copy [examples/mcpjungle/servers/labsnmp.json](../examples/mcpjungle/servers/labsnmp.json)
to `profiles/default/mcpjungle/servers/labsnmp.json`. Registrar env
must include `LABSNMP_TOKEN`.

```json
{
  "name": "labsnmp",
  "transport": "streamable_http",
  "url": "http://labsnmp:8088/mcp",
  "bearer_token": "${LABSNMP_TOKEN}"
}
```

Add `labsnmp` to the integration tool group (append, do not replace).

## Secrets

Mint `secrets/labsnmp-token` ≥32 bytes `0o644`.
Mint community files (`snmp-public`, `snmp-private`) and alice
auth/priv (`snmp-alice-auth`, `snmp-alice-priv`, ≥8 bytes).
`stageLabinfoCreds`. `LAB_DEV_MODE` reconciles from
`dev-credentials.yaml` fail-closed.

## Smoke

1. `snmpget -v2c -c public $HOST:$LABSNMP_AGENT_PORT 1.3.6.1.2.1.1.1.0`
2. `snmpget -v3 -u alice -l authPriv -a SHA-256 -A … -x AES -X … $HOST:$LABSNMP_AGENT_PORT 1.3.6.1.2.1.1.2.0`
3. Confirm community isolation: `public` cannot see private-only OIDs.
4. `snmptrap` v2c to `$LABSNMP_TRAP_PORT`; gateway `snmp_traps_wait`.

## Docs sweep in the integrator

README table, architecture mermaid, AGENTS.md rule 15 (161/162
native, 10161/10162 residual), configuration guide, CHANGELOG
`[Unreleased]`, Pages services.html.

Do not put codec or MIB logic in `internal/lab`.
