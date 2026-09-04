package snmpwire

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseOID parses a dotted numeric OID. A leading dot is accepted.
func ParseOID(s string) (OID, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, ".")
	if s == "" {
		return nil, fmt.Errorf("snmpwire: empty OID: %w", ErrOID)
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("snmpwire: OID needs at least two arcs: %w", ErrOID)
	}
	if len(parts) > maxOIDArcs {
		return nil, fmt.Errorf("snmpwire: OID too long: %w", ErrOID)
	}
	out := make(OID, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("snmpwire: empty OID arc: %w", ErrOID)
		}
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("snmpwire: OID arc %q: %w", p, ErrOID)
		}
		out[i] = uint32(v)
	}
	if out[0] > 2 {
		return nil, fmt.Errorf("snmpwire: OID first arc must be 0..2: %w", ErrOID)
	}
	if out[0] < 2 && out[1] > 39 {
		return nil, fmt.Errorf("snmpwire: OID second arc must be 0..39 when first is %d: %w", out[0], ErrOID)
	}
	return out, nil
}

func encodeOID(oid OID) ([]byte, error) {
	if len(oid) < 2 {
		return nil, fmt.Errorf("snmpwire: OID needs at least two arcs: %w", ErrOID)
	}
	if len(oid) > maxOIDArcs {
		return nil, fmt.Errorf("snmpwire: OID too long: %w", ErrOID)
	}
	if oid[0] > 2 {
		return nil, fmt.Errorf("snmpwire: OID first arc must be 0..2: %w", ErrOID)
	}
	if oid[0] < 2 && oid[1] > 39 {
		return nil, fmt.Errorf("snmpwire: OID second arc out of range: %w", ErrOID)
	}
	first := uint64(oid[0])*40 + uint64(oid[1])
	if first > 1<<32-1 {
		return nil, fmt.Errorf("snmpwire: OID first subidentifier overflow: %w", ErrOID)
	}
	buf := encodeSubID(nil, uint32(first))
	for _, a := range oid[2:] {
		buf = encodeSubID(buf, a)
	}
	return wrap(tagOID, buf), nil
}

func decodeOID(content []byte) (OID, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("snmpwire: empty OID contents: %w", ErrOID)
	}
	subs, err := decodeSubIDs(content)
	if err != nil {
		return nil, err
	}
	if len(subs) < 1 {
		return nil, fmt.Errorf("snmpwire: empty OID: %w", ErrOID)
	}
	if len(subs)+1 > maxOIDArcs {
		return nil, fmt.Errorf("snmpwire: OID too long: %w", ErrOID)
	}
	n := subs[0]
	var a0, a1 uint32
	switch {
	case n < 40:
		a0, a1 = 0, n
	case n < 80:
		a0, a1 = 1, n-40
	default:
		a0, a1 = 2, n-80
	}
	out := make(OID, 1+len(subs))
	out[0] = a0
	out[1] = a1
	copy(out[2:], subs[1:])
	return out, nil
}

func encodeSubID(dst []byte, v uint32) []byte {
	if v < 128 {
		return append(dst, byte(v))
	}
	var tmp [5]byte
	n := 0
	tmp[n] = byte(v & 0x7f)
	n++
	v >>= 7
	for v > 0 {
		tmp[n] = byte(v&0x7f) | 0x80
		n++
		v >>= 7
	}
	for i := n - 1; i >= 0; i-- {
		dst = append(dst, tmp[i])
	}
	return dst
}

func decodeSubIDs(b []byte) ([]uint32, error) {
	out := make([]uint32, 0, 8)
	var v uint64
	started := false
	for i, x := range b {
		if !started && x == 0x80 {
			return nil, fmt.Errorf("snmpwire: non-minimal OID subidentifier: %w", ErrOID)
		}
		v = (v << 7) | uint64(x&0x7f)
		if v > 1<<32-1 {
			return nil, fmt.Errorf("snmpwire: OID subidentifier overflow: %w", ErrOID)
		}
		started = true
		if x&0x80 == 0 {
			out = append(out, uint32(v))
			v = 0
			started = false
			continue
		}
		if i == len(b)-1 {
			return nil, fmt.Errorf("snmpwire: truncated OID subidentifier: %w", ErrOID)
		}
	}
	if started {
		return nil, fmt.Errorf("snmpwire: truncated OID subidentifier: %w", ErrOID)
	}
	return out, nil
}
