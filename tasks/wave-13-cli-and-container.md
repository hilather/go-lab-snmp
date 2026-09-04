# DEP-001 — CLI, image, compose.smoke

Status: not-started
Depends: AGENT-001, TRAP-001, API-001, OBS-001
Owns: Dockerfile, examples/compose.smoke.yaml, healthcheck

## Goal
Scratch UID 65532. test-container binds :1161/:1162. Interop with net-snmp CLI as client.
