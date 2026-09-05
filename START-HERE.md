# Start here

LabSNMP is a laboratory SNMP agent with a trap sink. Systems under
test speak SNMP. LabSNMP answers from a compiled OID map bound to
the community or v3 user.

If you want to **implement** it, read `AGENTS.md` then take a wave
from `tasks/00-program-board.md`. Do not invent capability IDs.

## Build

```
go build -o bin/labsnmp ./cmd/labsnmp
./bin/labsnmp version
```

`validate` and `canonicalize` load a fail-closed `labsnmp.dev/v1alpha1`
document. `serve --snmp-listen` binds the agent. `--management-listen`
defaults **off**. Trap stays unbound until TRAP-001.

```
./bin/labsnmp validate --config testdata/config/valid/full.yaml
./bin/labsnmp canonicalize --config testdata/config/valid/full.yaml
./bin/labsnmp serve --config testdata/config/valid/full.yaml \
  --snmp-listen=:1161
```

Interop (test machine with net-snmp tools):

```
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1.1.1.0
snmpwalk -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1.1
```

`--management-listen` defaults **off**.
