# USM-001 — Bounded v3 USM

Status: not-started
Depends: WIRE-001
Owns: internal/usm

## Goal
noAuthNoPriv / authNoPriv / authPriv with MD5, SHA-1, SHA-256 and DES, AES-128.

## Scope
- EngineID from spec or derived
- Time window on process clock
- Localized keys from passphrase files
- Report PDUs for usmStats.* failures
- Other algorithms reject at compile

## Tests
Interop with net-snmp snmpget -v3 -l authPriv -a SHA-256 -x AES.
Bad user / bad digest / time fail → Report, not panic.

## Acceptance
authPriv GET against testdata user alice succeeds; wrong passphrase does not.
