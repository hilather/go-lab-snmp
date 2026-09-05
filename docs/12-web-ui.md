# 12 — Operator UI

Status: Accepted
Owners: UI
Last reviewed: 2026-09-05
Related ADRs: 0004, 0005, 0007, 0009

Required for 1.0 GA. The operator SPA is a same-origin Vite + React 19 app
embedded with `go:embed` of `internal/web/dist`. It talks REST `/v1` only.
REST and MCP remain the control plane; the SPA is an adapter.

This is the **first** UI implementation (UI-001). The operator-SPA checklist
is signed off for **1.0.0** (PR 15).

## Screens

Exactly these routes. There is no send-trap control (ADR 0007).

| Path | Page |
|---|---|
| `/login` | Exchange a bearer for cookie `labsnmp_session` |
| `/` | Overview: ready, listeners (may include agent-tcp / traps-tcp / agent-dtls / traps-dtls), revisions, store stats |
| `/maps` | Map list |
| `/maps/:name` | Tree + leaf overlay edit (`POST /v1/maps/{name}/oids:set`) |
| `/communities` | Communities (wire strings / file contents never shown) |
| `/users` | Users (`secretFile` paths may show; contents never) |
| `/traps` | Trap inbox (receive-only; clear is overlay wipe, not originate) |
| `/traps/:id` | Trap detail + raw |
| `/queries` | Query ring (identity is community/user row name) |
| `/plan` | plan/apply (`snmp.admin`; `expectedRevision` from `GET /v1/state`) |
| `/reset` | Gated Reset (phrase `RESET`, `snmp.admin`) |
| `/audit` | Audit ring (`snmp.audit.read`) |
| `/features` | Frozen `features.list` live vs reset-only |
| `/status` | Ready, listeners (UDP plus optional TCP/DTLS dt/dd), hostTime, revisions |

`expectedRevision` comes from `GET /v1/state` `runtimeRevision` (camelCase).
Do not read nested Status revision keys for mutations.

Map overlay edit is `oids:set`. SET is overlay, not apply. Reset restores
bootstrap leaf values.

Communities list keeps `communityFile` paths. Users list keeps `secretFile`
paths. Neither page renders file contents or community wire strings.

Features page renders the frozen twelve ids. UI enablement is bootstrap YAML;
reread with Reset. Not a `features.list` id. Do not add `ui.enabled`, `dtls`,
or `tcp` ids.

Status and Overview keep the generic `status.listeners` list. `GET /v1/status`
listeners may include `agent-tcp`, `traps-tcp`, `agent-dtls`, and
`traps-dtls` when those transports are enabled (address `off` when that
plane is disabled). When `agent-tcp` or `agent-dtls` is present, Status and
Overview add explicit Agent TCP / Agent DTLS dt/dd rows. Still no feature
ids.

Reset rereads bootstrap YAML, drops the SET overlay, wipes traps and queries,
never writes the file. Phrase `RESET`, checkbox, optional reason. Submit
requires `snmp.admin`.

## Auth

Cookie `labsnmp_session` HttpOnly SameSite=Lax Path=/. CSRF header
`X-LabSNMP-CSRF` is held in process memory (`web/src/api/client.ts`). Never
`localStorage` / `sessionStorage` tokens. Never HTTP Basic. Vitest
`assertNoTokenStorage` locks this.

`GET`/`HEAD` never send CSRF. Mutations attach the in-memory secret.
`credentials: "same-origin"` always.

Login copy: exchange a scoped API bearer for an HttpOnly session cookie.

## `spec.ui.enabled`

`false` (or UI handler unset) → `GET /` is **404 `application/problem+json`**.
REST `/v1` and MCP `/mcp` are unchanged. Overlay BOM (`examples/` when
present) may keep `true`.

There is no live Apply op for `spec.ui`. Rewrite bootstrap YAML, then Reset
or process restart. `UIEnabled` in `cmd/labsnmp/serve.go` reads
`svc.Active().Canonical.Spec.UI.Enabled` and the compile-time
`web.UIEnabled` flag (true once dist is a real Vite tree).

`--management-listen` still defaults **off**.

## Origins

The SPA is **same-origin**. Overlay `allowedOrigins: []` stays deny-all
(no `*`). Missing Origin is allowed. Loopback (`http://127.0.0.1:8088`,
`http://localhost:5173` Vite) is exempt. A browser on a non-loopback Origin
gets **403** on `/v1/*` until the lab-owned overlay lists that origin
(scheme+host+port exact).

## Embed and CI

`make web-install web-test web-build web-embed` build the Vite app and copy
`web/dist` → `internal/web/dist`. Dockerfile has **no Node stage**. The
committed `internal/web/dist` is what `go:embed`, `go test`, `docker build`,
and GHCR ship.

CI job `web` (Node **22.14.0**) asserts the **checkout** is a real Vite tree
**before** `make web-build`: `internal/web/dist/index.html` has
`<title>LabSNMP</title>` or `#root`, the stub sentence is absent, hashed JS
exists. Then `web-install web-test web-build` proves `web/src` still
compiles. There is **no** full-tree `git diff` of `dist` (Vite is not
bit-identical across runners).

Go unit test `TestCommittedDistIsProduction` fails if `Files()` is the stub
page (`UI assets were not copied`). Tag-gate cannot publish a stub even if
the `web` YAML steps are reordered.

`internal/control/rest` production files must not import `internal/web`.
`cmd/labsnmp/serve.go` sets `rest.Config.UI`. Tests in `rest` may import `web`.

## Local Vite

Node **22.14.0**, npm ≥10.9.0.

```bash
make web-install
npm --prefix web run dev
```

Dev server proxies `/v1` and `/mcp` to `http://127.0.0.1:8088`. Serve LabSNMP
with `--management-listen=:8088` and `spec.ui.enabled: true`.

## Mira checklist

**Signed off for 1.0.0 on 2026-09-05 (PR 15).** Human Mira was not available;
sign-off is from the UI-001 tests below. This is a process gate for
**GA-001 / 1.0.0**, not for SWAP-001. No new capability IDs.

Mira is not a merge gate, tag gate, or GHCR gate. Security defects
(localStorage tokens, CSRF missing, Basic auth) remain a tag blocker because
CI must be green.

| Check | Evidence | 1.0.0 |
|---|---|---|
| Pages from this spec are present | Vitest `App.test.tsx` / `nav.test.ts`: `/login`, `/`, `/maps`, `/maps/:name`, `/communities`, `/users`, `/traps`, `/traps/:id`, `/queries`, `/plan`, `/reset`, `/audit`, `/features`, `/status` | pass |
| No localStorage / sessionStorage tokens | Vitest `assertNoTokenStorage`; cookie `labsnmp_session`; client tests assert empty web storage | pass |
| CSRF on mutations | `X-LabSNMP-CSRF` in process memory; GET/HEAD omit it; `MapDetailPage` `oids:set` + `PlanPage` apply tests | pass |
| `ui.enabled: false` → 404 problem+json | `TestSPADisabledIs404` / `TestServeUIDisabledIs404` | pass |
| No send-trap control | No UI for originating traps; Vitest `NoSendTrap`; ADR 0007 | pass |
| Cookie name | `labsnmp_session` HttpOnly SameSite=Lax Path=/ | pass |
| Committed dist is a real Vite tree | `TestCommittedDistIsProduction`; `internal/web/dist` has hashed JS; stub sentence absent | pass |

Operator SPA checklist signed off for 1.0.0.

**v1.1 (UI-110).** Status/Overview layout adds optional Agent TCP / Agent
DTLS dt/dd when those listeners are present. Features still twelve ids.
No send-trap. No token storage. No new capability IDs.

| Check | Evidence | 1.1 |
|---|---|---|
| Status/Overview TCP/DTLS rows when present | Vitest `StatusPage.test.tsx` / `OverviewPage.test.tsx` | pass |
| Features still twelve ids; no `dtls`/`tcp` ids | `FeaturesPage.test.tsx` | pass |
