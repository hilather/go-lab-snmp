# ADR 0010 — Container 161/162 and NET_BIND_SERVICE

Status: Accepted

Container listens `:161` and `:162`. Appliance tests use `:1161`/`:1162` with `cap_drop: ALL`. Integrator adds `NET_BIND_SERVICE` only when publishing IANA dests.
