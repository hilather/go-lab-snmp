# 11 — Deployment

Status: Proposed
Owners: Deployment
Last reviewed: 2026-09-05

Scratch image UID **65532:65532**, `CGO_ENABLED=0`, no Node stage,
no shell. Image `ghcr.io/hilather/labsnmp`. Config
`/etc/labsnmp/config.yaml`. The image is not buildable against the
API-001 unauthenticated `/v1` stub (DEP-001 depends on SEC-001).
Health live/ready stays unauthenticated; every other `/v1` and `/mcp`
route requires bearer or `labsnmp_session`.

## Image

```
CMD ["serve", "--config=/etc/labsnmp/config.yaml", "--management-listen=:8088"]
HEALTHCHECK CMD ["/labsnmp", "healthcheck", "--url=http://127.0.0.1:8088/v1/health/ready"]
EXPOSE 161/udp 162/udp 8088/tcp
USER 65532:65532
```

`--management-listen` still defaults **off** in the binary. The image
CMD binds `:8088` so HEALTHCHECK and authenticated `/v1` work.
Build stage is `golang:1.26-alpine` (any 1.26.x; not a hard
`1.26.6` pin). The operator SPA is `go:embed` of committed
`internal/web/dist`. `GET /` is 200 SPA HTML when `spec.ui.enabled`
is true; 404 `application/problem+json` when false. Tag-gate + GHCR
publish is `.github/workflows/release.yml` on `v*` after required CI
is green. v1.1 tags publish a multi-arch manifest list
(`linux/amd64`, `linux/arm64`); arm64 is publish-only and CI unit
jobs stay amd64. The digest of the manifest list is the pin.
`latest` still only on non-prerelease tags. TLS-001 stays deferred
(`dtls.enabled` / `tcp.enabled` true still reject).

## Appliance smoke vs integrator

Default `make test-container` runs `docker compose -f
examples/compose.smoke.yaml up --build` (fail closed without the
compose plugin). The file has `build.context: ..` so a clean tree
does not pull an unpublished `:test` tag. Smoke binds **`:1161` /
`:1162`** with `cap_drop: ALL` (no `NET_BIND_SERVICE`). Healthcheck
`start_period` is 3s (matches the image). Interop uses net-snmp CLI
as client when installed (skip if missing).

Integrator compose binds IANA **`:161` / `:162`** inside the
container and restores **only** `cap_add: [NET_BIND_SERVICE]`. Host
publish default is residual **10161/udp**, **10162/udp**, **18161/tcp**
([ADR 0014](adr/0014-host-residual-10161-10162.md)). Gated
`LABSNMP_TEST_NET_BIND=1` proves `:161`/`:162`+cap.

Docker must pass `NET_BIND_SERVICE` as an ambient capability to a
non-root process (dockerd ≥20.10 with default seccomp).
`no-new-privileges:true` is compatible because the cap is already in
the bounding set at exec.

## Host-publish UDP

Host-publish UDP may SNAT via Docker `userland-proxy` so every laptop
hitting `${LAB_PUBLIC_HOST}:10161` appears as one bridge IP (**NAT
collision**). LabSNMP keys views by community/user, not client IP, so
split-horizon still holds. Compose-network sources remain reliable
without turning `userland-proxy` off.

## Serve flags

| Flag | Default | Behavior |
|---|---|---|
| `--config` | required | bootstrap path |
| `--snmp-listen` | empty → YAML `:161` | `off` disables agent |
| `--trap-listen` | empty → YAML `:162` | `off` disables trap |
| `--management-listen` | **off** | YAML `management.address` does not bind unless this flag is an address. Image CMD `:8088`. |
| `--shutdown-timeout` | 10s | drain |
| `--pid-file` | empty | write pid after binds; write failure shuts down and exits 1; unlinked on shutdown |
