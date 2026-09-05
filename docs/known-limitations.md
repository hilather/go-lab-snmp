# Known limitations (1.1)

Residual 1.1 surface. RFC 3430 TCP and a DTLS 1.2 record layer are
schema-legal (`tcp.enabled` / `dtls.enabled` validate); those
listeners do not bind until later 1.1 PRs.

- Not a production agent. Not snmpd. Not a manager.
- No SMIv2 compiler. Numeric OIDs + optional aliases.
- v3 algs: MD5/SHA-1/SHA-256 + DES/AES-128 only. SHA-384/512 and
  AES-192/256 are `usm_alg_unsupported`.
- No AgentX. No trap forward or originate.
- DTLS is a record layer on IANA 10161/10162; inner PDU is community
  or USM. **TLSTM/TSM is not implemented.**
- RFC 6353 TLS-over-TCP (snmp-tls) is residual. No `spec.listeners.tls`.
  Catalog code `tls_unsupported` is retained for that residual and is
  not emitted on `tcp`/`dtls` enable.
- Trap remoteAddr is best-effort under Docker userland-proxy
  (**NAT collision** does not affect split-horizon; identity is
  community/user, not client IP).
- Single replica. Memory store only. Overlay and trap inbox wipe on
  reset/restart.
- No OAuth PRM.
- linux/arm64 is not in this tag.
- Integrator pin in mcp-integration-lab is out of band.
