# Examples

- `compose.smoke.yaml` — appliance smoke on `:1161`/`:1162` with
  `cap_drop: ALL`. Image CMD still binds management `:8088`.
- `labsnmp.yaml` — mcp-integration-lab bootstrap overlay
  (`public-if` / `private-if`, user `alice`). Copy to
  `profiles/default/labsnmp/bootstrap.yaml`.
- `labinfo/services-labsnmp.yaml` — catalog fragment, id `labsnmp`.
- `mcpjungle/servers/labsnmp.json` — Jungle registration
  (`bearer_token: ${LABSNMP_TOKEN}`).
- `mcpjungle/groups/integration.json` — append `labsnmp` to the
  integration tool group.

Integrator compose (IANA `:161`/`:162`, residual host
10161/10162/18161, `LABSNMP_REST_PORT`, `NET_BIND_SERVICE`) is in
`docs/13-integration-lab-swap.md`. Do not implement `vendor.go` here.
The YAML shape is in `docs/04-state-and-configuration.md`. Container
contract fixtures live in `testdata/container/`.
