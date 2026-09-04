# 13 — Integration with MCP Integration Lab

Status: Proposed
Owners: Integration
Last reviewed: 2026-09-04

Integrator change is LAST. This document is the BOM. Product logic
never moves into `mcplab`. There is **no** SNMP service in the lab
today — SWAP-001 adds it.

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

## Vendor pin

`internal/lab/vendor.go`:

```
URL:  https://github.com/hilather/go-lab-snmp
Dest: third_party/go-lab-snmp
Ref:  v1.0.0-rc.1
```

Do not edit `third_party/` in place.

## Compose (copy LabNTP)

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
10161/10162.

## profile.env

```
LABSNMP_AGENT_PORT=10161
LABSNMP_TRAP_PORT=10162
LABSNMP_REST_PORT=18161
```

IANA dest is 161/162. Residual is the shipped default because snmpd
and snmptrapd commonly hold those ports. Preflight occupancy is
`/proc/net` UDP bound. `EACCES` is not occupied. Error copy names
the fix: stop snmpd/snmptrapd, extra IP for `LAB_PUBLIC_HOST`, or
keep 10161/10162.

Also inject `LABSNMP_*` into the labinfo compose environment.

## labinfo

Id `labsnmp`. Must include `urls` + `connection` or labinfo fails
to start.

Connection endpoints:

- `snmp-agent` udp `${LAB_PUBLIC_HOST}:${LABSNMP_AGENT_PORT}`
  versions v1/v2c/v3, communities public/private, user alice
- `snmp-trap` udp `${LAB_PUBLIC_HOST}:${LABSNMP_TRAP_PORT}`
- MCP `http://${LAB_PUBLIC_HOST}:${LABSNMP_REST_PORT}/mcp`

Parameters: no TLS in 1.0, maps `public-if` / `private-if`,
auth none on v1/v2c data plane, v3 authPriv SHA-256/AES-128.

## Jungle

`profiles/default/mcpjungle/servers/labsnmp.json`:

```json
{
  "name": "labsnmp",
  "transport": "streamable_http",
  "url": "http://labsnmp:8088/mcp",
  "bearer_token": "${LABSNMP_TOKEN}"
}
```

Add `labsnmp` to the integration tool group.

## Secrets

Mint `secrets/labsnmp-token` ≥32 bytes `0o644`.
Mint community files and alice auth/priv (≥8 bytes).
`stageLabinfoCreds`. `LAB_DEV_MODE` reconciles from
`dev-credentials.yaml` fail-closed.

## Smoke

1. `snmpget -v2c -c public $HOST:$LABSNMP_AGENT_PORT 10.20.0.3.10.20.0.5.0`
2. `snmpget -v3 -u alice -l authPriv -a SHA-256 -A … -x AES -X … $HOST:$LABSNMP_AGENT_PORT 10.20.0.3.10.0.1.5.0`
3. Confirm community isolation: `public` cannot see private-only OIDs.
4. `snmptrap` v2c to `$LABSNMP_TRAP_PORT`; gateway `snmp_traps_wait`.

## Docs sweep in the integrator

README table, architecture mermaid, AGENTS.md rule 15 (161/162
native, 10161/10162 residual), configuration guide, CHANGELOG
`[Unreleased]`, Pages services.html.

Do not put codec or MIB logic in `internal/lab`.
