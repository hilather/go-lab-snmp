# ADR 0017 — Pin the Go toolchain patch

Status: Accepted (2026-10-08)

## Context

K19 in the shipped 1.0 design (`IMPLEMENTATION-DESIGN.md`) froze the
**Go 1.26 language** and deliberately did not pin a patch: no
`toolchain` line in `go.mod`, CI `go-version: "1.26"` (or any patch
setup-go can download), and a floating `golang:1.26-alpine` image.
That kept the pack buildable on any installed 1.26.x.

Go stdlib security fixes now land in patch releases that govulncheck
checks for (GO-2026-6603–6605, GO-2026-6607–6613 and GO-2026-6617 are
fixed only in go1.26.9). A floating image or an older local patch
silently builds with a vulnerable stdlib, and the go-lab family has
moved to one exact patch across repos.

## Decision

- `go.mod` keeps `go 1.26.0` (the 1.26 language) and adds
  `toolchain go1.26.9`.
- CI and release `actions/setup-go` pin `go-version: "1.26.9"`.
- The build image is `golang:1.26.9-alpine`; `TestDockerfileContract`
  enforces that tag.
- Patch bumps follow the go-lab family: one PR moves `go.mod`
  `toolchain`, CI, the image and the contract test together.
- `mise.toml` stays `go = "1.26"`; with the default `GOTOOLCHAIN=auto`
  the `toolchain` line makes an older local 1.26.x fetch go1.26.9.

This supersedes K19's "any 1.26.x / no toolchain line / do not
hard-pin the image" bullets and the matching Go row in
`IMPLEMENTATION-DESIGN-v1.1.md`. Both design files are shipped records
(v1.0.0, v1.1.0) and are not edited; read them together with this ADR.

## Consequences

Builds need go1.26.9 (downloaded automatically under
`GOTOOLCHAIN=auto`). Each stdlib security patch is a deliberate,
reviewed bump instead of an implicit float.
