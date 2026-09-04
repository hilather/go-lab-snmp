# Security

LabSNMP is laboratory software. It is not a production SNMP agent.

- Management requires a file-referenced bearer ≥32 bytes.
- SNMPv1/v2c communities are cleartext identifiers. Treat them as lab handles, not secrets.
- SNMPv3 auth/priv keys are secrets and must be file refs.
- The appliance never forwards or originates traps. Treat any forward feature as a security regression unless an ADR supersedes ADR 0007.

Report issues against https://github.com/hilather/go-lab-snmp.
