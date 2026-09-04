# 05 — Control plane and parity

Last reviewed: 2026-09-04

REST and MCP are adapters over one `internal/app.Service`. They must
not call each other. Implementation order CFG → APP → API → SEC → MCP.

## Frozen capabilities

REST_ONLY_PROTOCOL: health live/ready, session, metrics scrape, SPA.

PARITY_REQUIRED:

| REST | MCP | Scope |
|---|---|---|
| `GET /v1/version` | `snmp_version_get` | `snmp.read` |
| `GET /v1/capabilities` | `snmp_capabilities_get` | `snmp.read` |
| `GET /v1/status` | `snmp_status_get` | `snmp.read` |
| `GET /v1/schema/config` | `snmp_schema_get` | `snmp.read` |
| `GET /v1/features` | `snmp_features_list` | `snmp.read` |
| `GET /v1/state` | `snmp_state_get` | `snmp.read` |
| `POST /v1/state:validate` | `snmp_state_validate` | `snmp.admin` |
| `GET /v1/state:export` | `snmp_state_export` | `snmp.admin` |
| `POST /v1/state:reset` | `snmp_state_reset` | `snmp.admin` |
| `POST /v1/changes:plan` | `snmp_change_plan` | `snmp.admin` |
| `POST /v1/changes:apply` | `snmp_change_apply` | `snmp.admin` |
| `GET /v1/maps` | `snmp_maps_list` | `snmp.read` |
| `GET /v1/maps/{name}` | `snmp_map_get` | `snmp.read` |
| `POST /v1/maps/{name}:query` | `snmp_map_query` | `snmp.read` |
| `POST /v1/maps/{name}/oids:set` | `snmp_oid_set` | `snmp.write` |

| `POST /v1/maps/{name}/oids:get` | `snmp_oid_get` | | `snmp.read` |
| `GET /v1/queries` | `snmp_queries_list` | `labsnmp://queries` | `snmp.read` |
| `GET /v1/preview/get` | `snmp_preview_get` | | `snmp.read` |
| `GET /v1/communities` | `snmp_communities_list` | `snmp.read` |
| `GET /v1/users` | `snmp_users_list` | `snmp.read` |
| `GET /v1/traps` | `snmp_traps_list` | `snmp.read` |
| `GET /v1/traps/{id}` | `snmp_trap_get` | `snmp.read` |
| `GET /v1/traps/{id}/raw` | `snmp_trap_raw_get` | `snmp.read` |
| `POST /v1/traps:wait` | `snmp_traps_wait` | `snmp.read` |
| `POST /v1/traps:clear` | `snmp_traps_clear` | `snmp.write` |
| `GET /v1/stats` | `snmp_stats_get` | `snmp.read` |
| `GET /v1/audit` | `snmp_audit_query` | `snmp.audit.read` |
| `GET /v1/audit/{id}` | `snmp_audit_get` | `snmp.audit.read` |

Resources: `labsnmp://state`, `labsnmp://maps`, `labsnmp://maps/{name}`,
`labsnmp://traps`, `labsnmp://traps/{id}`, `labsnmp://stats`,
`labsnmp://capabilities`, `labsnmp://status`, `labsnmp://features`.

`snmp_map_query` simulates GET/GETNEXT/GETBULK against a named map
without sending a datagram (agent-side preview).

`snmp_users_list` redacts secret paths' contents; paths themselves
may appear.

Scopes: `snmp.read` `snmp.write` `snmp.admin` `snmp.audit.read`.
Administrator has all. Reader has `snmp.read`.

## Errors

`application/problem+json` with `code`. Frozen codes include
`validation_failed`, `unknown_field`, `reserved_key`, `immutable_field`,
`revision_mismatch`, `not_found`, `not_writable`, `wrong_type`,
`wait_timeout`, `store_wiped`, `unauthorized`, `forbidden`,
`origin_not_allowed`, `tls_unsupported`, `no_such_instance`,
`end_of_mib_view`.
