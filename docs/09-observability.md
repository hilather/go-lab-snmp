# 09 — Observability

Status: Proposed
Owners: Observability
Last reviewed: 2026-09-05

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
| `labsnmp_listeners_bound` | gauge | `component` (`agent`, `traps`, `management`, `agent-tcp`, `traps-tcp`, `agent-dtls`, `traps-dtls`). 1 if bound, 0 if enabled-but-unbound, omitted if off |

Internal: `labsnmp_telemetry_dropped_total{reason}` counts rejected samples (forbidden labels, unknown names, cardinality).

Never label with client IP, community strings, tokens, or USM secrets.

Do not add a `transport` label to `labsnmp_pdus_total`. Events stay
`snmp.pdu` / `snmp.trap`.

`GET /v1/metrics` is OpenMetrics text. Served unauthenticated when
`observability.metrics.publicPath` is true; otherwise 404 until a
bearer scrape (SEC-001).

## Health

`GET /v1/health/live` — process (management HTTP up).
`GET /v1/health/ready` — snapshot installed AND every **enabled**
data-plane listener bound AND (management bound OR
`--management-listen=off`). Disabled TCP/DTLS (default
`tcp.enabled` / `dtls.enabled` false) do not demand a bind. Ready
stays true on the old sockets until a new bind succeeds. A management
move binds the new listener before the old one stops accepting
(`Bound` is true on the new listener as soon as Listen succeeds).
The old management server then drains in the background for up to
5s, and remaining connections are closed. Turning management off
stops accepting at once, clears `Bound`, and uses the same drain.
Process shutdown also waits for a background drain, bounded by
`--shutdown-timeout`.

`GET /v1/status` `listeners[]` always includes `agent`, `traps`,
and `management`. It may include `agent-tcp`, `traps-tcp`,
`agent-dtls`, and `traps-dtls` when those transports are enabled
(address `off` when that plane is disabled). Listener enable remains
reset-only.

`labsnmp healthcheck --url=http://127.0.0.1:8088/v1/health/ready`.

Events: `snmp.pdu`, `snmp.trap`, `state.apply`, `state.reset`,
`auth.failure`, `http.request`.
