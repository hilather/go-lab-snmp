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
document. `serve --snmp-listen` binds the agent. `--trap-listen` empty
uses YAML (`:162` by default); pass `:1162` locally. `--management-listen`
defaults **off**.

```
./bin/labsnmp validate --config testdata/config/valid/full.yaml
./bin/labsnmp canonicalize --config testdata/config/valid/full.yaml
./bin/labsnmp serve --config testdata/config/valid/full.yaml \
  --snmp-listen=:1161 --trap-listen=:1162
```

Interop (test machine with net-snmp tools):

```
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1.1.1.0
snmpwalk -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1.1
snmptrap -v2c -c public 127.0.0.1:1162 '' 1.3.6.1.6.3.1.1.5.1
```

`--management-listen` defaults **off**. The scratch image CMD binds
`:8088` so HEALTHCHECK and authenticated `/v1` work. Appliance smoke
is `:1161`/`:1162` with `cap_drop: ALL` (`make test-container`).
With `--management-listen=:8088` and `spec.ui.enabled: true`, `GET /`
serves the operator SPA.

```
make web-install web-test web-build
```
