# 09 — Observability

Status: Proposed
Owners: Observability
Last reviewed: 2026-09-04

slog JSON to stderr. Hand-rolled OpenMetrics. No Prometheus client.

Series: `labsnmp_pdus_total{version,pdu,decision}`,
`labsnmp_traps_total{version,decision}`,
`labsnmp_store_messages`, `labsnmp_store_bytes`,
`labsnmp_apply_total{result}`, `labsnmp_http_requests_total{code,route}`,
`labsnmp_build_info`.

Ready: snapshot loaded AND enabled agent/trap listeners bound AND
(management bound or off). `labsnmp healthcheck --url=`.
