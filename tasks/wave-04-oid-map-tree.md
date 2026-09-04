# MAP-001 — OID map tree

Status: not-started
Depends: CFG-001
Owns: internal/mibtree

## Goal
Compile a map into a lex-ordered tree. GET, GETNEXT, GETBULK, SET-check.

## Scope
- Dotted OID parse/normalize
- noSuchObject vs noSuchInstance vs endOfMibView
- maxRepetitions cap
- access + type + range checks for SET (overlay apply is APP-001)

## Tests
Lex order across 1.3.6 vs 1.3.6.1; table rows; empty map; duplicate OID rejected at compile.

## Acceptance
snmpwalk-equivalent GETNEXT loop over testdata map returns every leaf once.
