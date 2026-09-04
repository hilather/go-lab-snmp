# Known limitations (1.0)

- Not a production agent. Not snmpd. Not a manager.
- No SMIv2 compiler. Numeric OIDs + optional aliases.
- v3 algs: MD5/SHA-1/SHA-256 + DES/AES-128 only.
- No TCP/DTLS SNMP. No AgentX. No trap forward or originate.
- Trap remoteAddr best-effort under Docker userland-proxy.
- Single replica. Memory store only.
- No OAuth PRM.
