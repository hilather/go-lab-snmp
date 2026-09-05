# CFG-001 — Domain and fail-closed YAML

Status: not-started
Depends: FND-001
Owns: internal/model, internal/config, testdata/config, api/jsonschema

## Goal
labsnmp.dev/v1alpha1 loads, normalizes, rejects unknown and reserved keys, prints revision.

## Scope
- Spec structs for listeners, auth, engine, agent, admission, maps, communities, users, traps, ui, management
- KnownFields(true), camelCase only
- reserved-key reject list from AGENTS.md
- canonicalize + validate CLI
- dtls.enabled/tcp.enabled true reject
- map reference must exist; unique community strings; unique user names
- token ≥32; v3 secrets file refs ≥8

## Tests
valid/defaults.yaml, valid/split-horizon.yaml, invalid/* for each reject class, revision stability.

## Acceptance
`labsnmp validate` exits 0 on testdata/config/valid and 2 on invalid.
