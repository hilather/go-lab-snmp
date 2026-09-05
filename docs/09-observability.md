# 09 — Observability

Status: Proposed
Owners: Observability
Last reviewed: 2026-09-04

slog JSON to stderr. Hand-rolled OpenMetrics. No Prometheus client.

## Metrics

| Metric | Kind | Labels |
|---|---|---|
| `labsnmp_pdus_total` | counter | `version`, `pdu`, `decision` (`ok`, `drop`, `auth_fail`, `allowlist`, `admission`, `version`, `oversize`, `decode`, `unmatched`) |
| `labsnmp_traps_total` | counter | `version`, `decision` (same decision set; stored traps are `ok`) |
| `labsnmp_store_messages` | gauge | — |
| `labsnmp_store_bytes` | gauge | — |
| `labsnmp_apply_total` | counter | `result` (`ok`, `error`, `conflict`) |
| `labsnmp_http_requests_total` | counter | `code`, `route` (REST path template; unmatched is `other`) |
| `labsnmp_build_info` | gauge | `version`, `commit` |
| `labsnmp_auth_fail_total` | counter | `version` (`v1`, `v2c`, `v3`) |

Internal: `labsnmp_telemetry_dropped_total{reason}` counts rejected samples (forbidden labels, unknown names, cardinality).

Never label with client IP, community strings, tokens, or USM secrets.

`GET /v1/metrics` is OpenMetrics text. Served unauthenticated when
`observability.metrics.publicPath` is true; otherwise 404 until a
bearer scrape (SEC-001).

## Health

`GET /v1/health/live` — process (management HTTP up).
`GET /v1/health/ready` — snapshot installed AND every enabled
agent/trap listener bound AND (management bound OR
`--management-listen=off`). Ready stays true on the old sockets until
a new bind succeeds.

`labsnmp healthcheck --url=http://127.0.0.1:8088/v1/health/ready`.

Events: `snmp.pdu`, `snmp.trap`, `state.apply`, `state.reset`,
`auth.failure`, `http.request`.
