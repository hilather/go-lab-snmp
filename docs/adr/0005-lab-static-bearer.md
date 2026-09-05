# ADR 0005 — Lab static bearer

Status: Accepted
Date: 2026-09-04
Related: D10, SEC-001

`spec.auth.mode: bearer` only. Token file-ref ≥32 bytes. SHA-256 digest
compare. Cookie `labsnmp_session` HttpOnly SameSite=Lax Path=/. CSRF
`X-LabSNMP-CSRF` in process memory. No Basic, no OAuth PRM. Roles
`administrator` / `reader` only. Management bind requires ≥1 usable
token unless listen is off. Health stays unauthenticated.
