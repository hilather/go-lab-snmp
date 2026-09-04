# 06 — REST API

Status: Proposed
Owners: Control Plane
Last reviewed: 2026-09-04

Frozen routes live in `05-control-plane-and-parity.md`.
problem+json. Bearer or session+CSRF. Health is unauthenticated.

`POST /v1/maps/{name}/oids:get` and `:set` take `{oid, value?}`.
`:set` is overlay. `GET /v1/preview/get` evaluates a community or
user + oid against the compiled tree without sending a wire packet.

`GET /v1/queries` is a last-N PDU ring (request type, identity,
decision, error status) for the operator UI. No payloads of USM
keys or community strings.
