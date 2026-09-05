# Known limitations (1.1)

Residual 1.1 surface. RFC 3430 TCP and a DTLS 1.2 record layer are
schema-legal (`tcp.enabled` / `dtls.enabled` validate). Agent and trap
TCP/DTLS bind at serve and through Reset-driven Sync. Serve may start
with agent UDP off if TCP or DTLS agent is on. pion/dtls v3.1.8 cannot
round-trip DTLS application records ≳8KiB (no application-data
fragmentation; 8192-byte inbound buffer).

- Not a production agent. Not snmpd. Not a manager.
- No SMIv2 compiler. Numeric OIDs + optional aliases.
- v3 algs: MD5/SHA-1/SHA-256 + DES/AES-128 only. SHA-384/512 and
  AES-192/256 are `usm_alg_unsupported`.
- No AgentX. No trap forward or originate.
- DTLS is a record layer on IANA 10161/10162; inner PDU is community
  or USM. **TLSTM/TSM is not implemented.** pion/dtls v3.1.8 does
  not fragment DTLS application data and reads UDP into 8192 bytes,
  so a ≥8KiB SNMP Response cannot round-trip on DTLS.
- RFC 6353 TLS-over-TCP (snmp-tls) is residual. No `spec.listeners.tls`.
  Catalog code `tls_unsupported` is retained for that residual and is
  not emitted on `tcp`/`dtls` enable.
- Trap remoteAddr is best-effort under Docker userland-proxy
  (**NAT collision** does not affect split-horizon; identity is
  community/user, not client IP).
- Single replica. Memory store only. Overlay and trap inbox wipe on
  reset/restart.
- No OAuth PRM.
- Integrator pin in mcp-integration-lab is out of band.
