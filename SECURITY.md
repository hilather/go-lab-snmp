# Security

LabSNMP is laboratory software. It is not a production SNMP agent.

- Management requires a file-referenced bearer ≥32 bytes.
- SNMPv1/v2c communities are cleartext **on the wire** (SNMP has no
  confidentiality) but **config** stores them as `communityFile` refs
  so bootstrap YAML stays non-secret. Treat the wire string as a lab
  handle, not a production secret.
- SNMPv3 auth/priv keys are secrets and must be file refs.
- The appliance never forwards or originates traps. Treat any forward feature as a security regression unless an ADR supersedes ADR 0007.

Report issues against https://github.com/hilather/go-lab-snmp.
