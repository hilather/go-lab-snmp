# 04 — State and configuration

Status: Proposed
Owners: Configuration
Last reviewed: 2026-09-05

Desired state is one YAML document. SET overlay and traps are not
desired state. The process never writes the bootstrap file.

## Document

```
apiVersion: labsnmp.dev/v1alpha1
kind: LabSNMP
metadata:
  name: <dns-label>
spec: { ... }
```

`KnownFields(true)`. camelCase wire names. kebab aliases reject.

## Field map

### spec.listeners

| Field | Default | Notes |
|---|---|---|
| `agent.enabled` | true | |
| `agent.address` | `:161` | reset-only |
| `traps.enabled` | true | |
| `traps.address` | `:162` | reset-only |
| `tcp.enabled` | false | schema-legal; reset-only |
| `tcp.address` | empty | inherit UDP agent host:port only if UDP agent is on |
| `tcp.trapsAddress` | empty | inherit UDP trap host:port only if UDP trap is on |
| `dtls.enabled` | false | schema-legal; reset-only |
| `dtls.address` | `:10161` when enabled | must not collide with agent UDP |
| `dtls.trapsAddress` | `:10162` when enabled | must not collide with trap UDP |
| `dtls.certFile` | required if enabled | file ref |
| `dtls.keyFile` | required if enabled | file ref |
| `dtls.clientCAFile` | empty | optional file ref |
| `management.address` | empty | off unless CLI flag |
| `management.restPath` | `/v1` | |
| `management.mcpPath` | `/mcp` | |

`tcp.enabled: true` with both resulting TCP addresses off is
`validation_failed`. Empty TCP addresses do not bind when the matching
UDP listener is off. `dtls.enabled: true` requires `certFile` and
`keyFile` (resolved CWD then the config directory, then
`tls.LoadX509KeyPair`). There is no `spec.listeners.tls`. These keys
are schema-legal in 1.1. Agent and trap TCP/DTLS bind through the
agent/sink and Reset Sync. Serve's initial bind set is still UDP
until serve flags land.

### spec.auth

Bearer only. `spec.management.auth` is unknown and rejects.

| Field | Default |
|---|---|
| `mode` | `bearer` |
| `tokens[].id` | required |
| `tokens[].role` | `administrator` or `reader` |
| `tokens[].secretFile` | required, ≥32 bytes |

### spec.engine

| Field | Default |
|---|---|
| `engineID` | derived `8000` + enterprise `0` + `labsnmp` + hostname hash |
| `engineBoots` | 1 |

Never call `settimeofday`. Engine time is process clock.

### spec.agent

| Field | Default |
|---|---|
| `versions` | `[v1, v2c, v3]` |
| `maxVarBinds` | 64 |
| `maxRepetitions` | 100 |
| `maxMessageBytes` | `64KiB` |

### spec.admission

| Field | Default |
|---|---|
| `allowClientCidrs` | loopback if omitted; lab overlay sets `10.99.42.0/24` |
| `maxDatagramsPerSec` | 10000 |
| `maxDatagramsPerIP` | 500 |

### spec.maps[] / spec.communities[] / spec.users[]

See [03-mib-and-trap-store.md](03-mib-and-trap-store.md) and
[02-snmp-semantics.md](02-snmp-semantics.md).

Community `name` is a required unique DNS-label **row id**
(REST/MCP/UI). `communityFile` is required. The wire community octet
string is the trimmed file contents. Inline `community:`, using `name`
as the wire string, or `secretFile` on a community row is an unknown
or validate error.

At least one community **or** one user is required if any agent-plane
listener will bind (UDP agent, agent TCP, or agent DTLS). Each `map`
reference must exist. Community **wire strings** must be unique after
file resolution. User names must be unique. At least one agent-plane
listener must remain possible.

`valueFrom: uptime` is the only dynamic source. The leaf must be
`type: timeTicks` and `access: read` (or omitted). It is never writable.

v3 user:

```yaml
users:
  - name: alice
    level: authPriv          # noAuthNoPriv | authNoPriv | authPriv
    auth:
      protocol: sha256       # md5 | sha1 | sha256
      secretFile: /run/secrets/snmp-alice-auth
    priv:
      protocol: aes128       # des | aes128
      secretFile: /run/secrets/snmp-alice-priv
    access: read-write
    map: private-if
```

Auth/priv secrets ≥8 bytes (USM passphrase floor). File refs only.

### spec.traps

| Field | Default |
|---|---|
| `maxMessages` | 1000 |
| `maxBytes` | `16MiB` |
| `fullPolicy` | `evict_oldest` |
| `maxWait` | `60s` |
| `acceptUnauthenticated` | false |
| `rawRetain` | true |

### spec.ui / spec.management / spec.observability

Mirror LabNTP: `ui.enabled` default true; `management.mcp.allowLegacyClients`
default false (lab overlay true); `allowedOrigins` default `[]`;
`bodyLimit` `1MiB`; `logLevel` `info`; `metrics.publicPath` false.

## Revision

SHA-256 of canonical YAML. Secret **paths** included, secret **bytes**
never. SET overlay does not change revision. `storeGeneration` does.

## Live vs reset-only

| Live via plan/apply | Reset-only | Data-plane overlay |
|---|---|---|
| replaceMaps / upsertMap / removeMap | listener addresses | SET / `oids:set` |
| replaceCommunities / upsert / remove | auth tokens | trap insert |
| replaceUsers / upsert / remove | engineID | |
| replaceTrapStorePolicy | dtls/tcp flags | |
| replaceAdmission | ui.enabled, management.address | |
| replaceAgentCaps | | |

## Closed apply operations (1.0)

`replaceMaps`, `upsertMap`, `removeMap`,
`replaceCommunities`, `upsertCommunity`, `removeCommunity`,
`replaceUsers`, `upsertUser`, `removeUser`,
`replaceTrapStorePolicy`, `replaceAdmission`, `replaceAgentCaps`,
`replaceObservability`.

Apply requires `expectedRevision` + `Idempotency-Key`.
Mismatch returns `revision_mismatch` with `currentRevision`.

`oids:set` body is a single `{oid, value}`. It writes the same SET overlay
as SNMP SET and is not an apply verb. Overlay does not change revision;
`storeGeneration` does.

Reset: reread bootstrap, drop overlay, wipe traps and the query ring,
rebind UDP agent and trap sockets (bind-new-first; empty address stops
that listener), swap snapshot, increment `storeGeneration`. Never writes
the file. CLI listen flags still win after Reset.
