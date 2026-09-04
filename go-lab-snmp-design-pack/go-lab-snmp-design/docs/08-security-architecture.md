# 08 — Security architecture

- Management: `spec.auth` bearer file-ref ≥32 bytes. Cookie
  `labsnmp_session`. CSRF `X-LabSNMP-CSRF`. Origins exact match.
- Data plane v1/v2c: community string from file. Treat as a shared
  secret. Prefer long random values in non-dev profiles.
- Data plane v3: USM. Time window 150s. Localized keys at compile.
- Trap sink: unauthenticated beyond community/user on the PDU.
  Anyone who can reach 162 can fill the store — admission CIDRs.
- No trap forward (no amplifier).
- Secrets never in GET state, UI, logs at info, or metrics labels.
