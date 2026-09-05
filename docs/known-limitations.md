# Known limitations (1.0)

Residual 1.0 surface. TLS-001 (DTLS / TCP SNMP) stays deferred:
`spec.listeners.dtls.enabled: true` and `spec.listeners.tcp.enabled: true`
still reject (`tls_unsupported`).

- Not a production agent. Not snmpd. Not a manager.
- No SMIv2 compiler. Numeric OIDs + optional aliases.
- v3 algs: MD5/SHA-1/SHA-256 + DES/AES-128 only. SHA-384/512 and
  AES-192/256 are `usm_alg_unsupported`.
- No TCP/DTLS SNMP. No AgentX. No trap forward or originate.
- Trap remoteAddr is best-effort under Docker userland-proxy
  (**NAT collision** does not affect split-horizon; identity is
  community/user, not client IP).
- Single replica. Memory store only. Overlay and trap inbox wipe on
  reset/restart.
- No OAuth PRM.
- linux/arm64 is not in this tag.
- Integrator pin in mcp-integration-lab is out of band.
