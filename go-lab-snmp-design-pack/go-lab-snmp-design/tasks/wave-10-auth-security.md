# SEC-001 — Bearer, CSRF, audit

Status: not-started
Depends: API-001
Owns: internal/auth, internal/audit

## Goal
spec.auth bearer. Cookie session + CSRF. Audit ring. MCP still not public without token.

## Tests
401 without token; CSRF required on cookie mutating REST; users list redacted; short token rejected at validate.
