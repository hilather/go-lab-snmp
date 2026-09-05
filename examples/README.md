# Examples

- `compose.smoke.yaml` — appliance smoke on `:1161`/`:1162` with
  `cap_drop: ALL`. Image CMD still binds management `:8088`.

Shipped after SWAP-001:

- `labsnmp.yaml` — bootstrap with public/private maps + alice
- `labinfo/services-labsnmp.yaml`
- `mcpjungle/servers/labsnmp.json`

Until SWAP-001, the YAML shape is in
`docs/04-state-and-configuration.md` and the integrator checklist
is `docs/13-integration-lab-swap.md`. Container contract fixtures
live in `testdata/container/`.
