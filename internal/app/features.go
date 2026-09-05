package app

import "github.com/hilather/go-lab-snmp/internal/capabilities"

// Features is the frozen operator catalog from docs/04 live vs reset-only
// rows (K20). Do not list ui.enabled. Do not mint dtls/tcp feature ids.
func Features() []Feature {
	return capabilities.Features()
}
