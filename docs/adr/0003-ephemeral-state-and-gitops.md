# ADR 0003 — Ephemeral state and GitOps

Status: Accepted

YAML is desired state (`KnownFields(true)`, camelCase). Runtime SET overlay and trap inbox are ephemeral. Reset rereads bootstrap and never writes it.
