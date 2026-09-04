# 11 — Deployment

Status: Proposed
Owners: Deployment
Last reviewed: 2026-09-04

Scratch image UID 65532. CMD serve
`--config=/etc/labsnmp/config.yaml --management-listen=:8088`.
Healthcheck hits `/v1/health/ready`.

Appliance smoke: `:1161` / `:1162`, `cap_drop: ALL`.
Integrator: host 10161/10162/18161, `NET_BIND_SERVICE` only if
publishing 161/162.

Flags: `--snmp-listen`, `--trap-listen` (`off` allowed),
`--management-listen` (default off).
