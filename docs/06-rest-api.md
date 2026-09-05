# 06 — REST API

Status: Proposed
Owners: Control Plane
Last reviewed: 2026-09-04

Frozen routes live in `05-control-plane-and-parity.md`.
`application/problem+json` (RFC 9457). Bearer or session+CSRF.
Health live/ready is unauthenticated. `GET /v1/metrics` is public
only when `observability.metrics.publicPath` is true. Cookie
`labsnmp_session` + header `X-LabSNMP-CSRF` on cookie mutations.

`POST /v1/maps/{name}:query` body is `{pdu, oids, nonRepeaters?,
maxRepetitions?}`. `pdu` is `get`, `getNext`, or `getBulk`. It
simulates the named map without sending a datagram.

`POST /v1/maps/{name}/oids:get` and `:set` take `{oid, value?}`.
`:set` is overlay. Extra keys or an oid array are `unknown_field` /
`validation_failed`. `GET /v1/preview/get` evaluates a community or
user + oid against the compiled tree without sending a wire packet
(`community` **or** `user`, and `oid`).

`GET /v1/state:export` defaults to the canonical document as YAML
(`Content-Type: application/yaml`). `?format=json` writes the same
document as `application/json`. Revision is `X-LabSNMP-Revision` for
both; there is no JSON envelope.

`POST /v1/traps:wait` waits for an existing or later matching trap.
`wait_timeout` is 504. Wipe during wait is `store_wiped`.

`GET /v1/features` is the K20 live vs reset-only catalog only. Do
not list `ui.enabled`. Do not mint `dtls` / `tcp` feature ids.

`GET /v1/queries` is a last-N PDU ring (request type, identity,
decision, error status) for the operator UI. No payloads of USM
keys or community strings.

`--management-listen` default off. YAML `management.address` does
not bind unless the flag is an address. `GET /` is 404 problem+json
until UI-001 (and while `ui.enabled: false`).
