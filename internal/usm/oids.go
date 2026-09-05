package usm

import "github.com/hilather/go-lab-snmp/internal/snmpwire"

// RFC 3414 usmStats scalars (instance .0). Report-only unless a YAML map
// happens to contain the same OIDs; this package does not inject them.
var (
	OIDUnsupportedSecLevels = snmpwire.OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0}
	OIDNotInTimeWindows     = snmpwire.OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0}
	OIDUnknownUserNames     = snmpwire.OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0}
	OIDUnknownEngineIDs     = snmpwire.OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0}
	OIDWrongDigests         = snmpwire.OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0}
	OIDDecryptionErrors     = snmpwire.OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0}
)

// TimeWindow is the RFC 3414 +/- 150 second authoritative window.
const TimeWindow = 150
