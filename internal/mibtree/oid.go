package mibtree

import (
	"fmt"
	"strconv"
	"strings"
)

// OID is a sequence of SNMP sub-identifiers. Comparison is numeric on
// arcs: 1.3.6 precedes 1.3.6.1, and 1.3.6 precedes 1.3.10.
type OID []uint32

// ParseOID parses a dotted numeric identifier. Leading dots and extra
// zeros that change identity (1.03.6) are rejected.
func ParseOID(s string) (OID, error) {
	if s == "" {
		return nil, fmt.Errorf("oid is empty")
	}
	if strings.TrimSpace(s) != s {
		return nil, fmt.Errorf("oid is not a dotted numeric identifier")
	}
	if strings.HasPrefix(s, ".") {
		return nil, fmt.Errorf("oid must not have a leading dot")
	}
	parts := strings.Split(s, ".")
	out := make(OID, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("oid contains an empty arc")
		}
		if len(p) > 1 && p[0] == '0' {
			return nil, fmt.Errorf("oid arcs must not have leading zeros")
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return nil, fmt.Errorf("oid must be dotted numeric")
			}
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("oid arc is not a uint32")
		}
		out = append(out, uint32(n))
	}
	return out, nil
}

// String returns the dotted form without a leading dot. A nil or empty
// OID is the empty string.
func (oid OID) String() string {
	if len(oid) == 0 {
		return ""
	}
	var b strings.Builder
	for i, a := range oid {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(a), 10))
	}
	return b.String()
}

// Equal reports whether a and b have the same arcs.
func (oid OID) Equal(other OID) bool {
	return Compare(oid, other) == 0
}

// PrefixOf reports whether oid is a proper prefix of other.
func (oid OID) PrefixOf(other OID) bool {
	if len(oid) >= len(other) {
		return false
	}
	for i := range oid {
		if oid[i] != other[i] {
			return false
		}
	}
	return true
}

// Compare returns -1, 0, or 1 as a is less than, equal to, or greater
// than b in SNMP lexicographic order.
func Compare(a, b OID) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

func cloneOID(oid OID) OID {
	if oid == nil {
		return nil
	}
	out := make(OID, len(oid))
	copy(out, oid)
	return out
}
