package snmpwire

import (
	"encoding/binary"
	"fmt"
)

const (
	tagInteger     byte = 0x02
	tagOctetString byte = 0x04
	tagNull        byte = 0x05
	tagOID         byte = 0x06
	tagSequence    byte = 0x30

	tagIPAddress byte = 0x40
	tagCounter32 byte = 0x41
	tagGauge32   byte = 0x42
	tagTimeTicks byte = 0x43
	tagOpaque    byte = 0x44
	tagCounter64 byte = 0x46

	tagNoSuchObject   byte = 0x80
	tagNoSuchInstance byte = 0x81
	tagEndOfMibView   byte = 0x82

	tagPDUBase byte = 0xa0
)

type reader struct {
	b []byte
	i int
}

func newReader(b []byte) reader { return reader{b: b} }

func (r *reader) remaining() int { return len(r.b) - r.i }

func (r *reader) take(n int) ([]byte, error) {
	if n < 0 || r.i > len(r.b) || n > len(r.b)-r.i {
		return nil, fmt.Errorf("%w", ErrTruncated)
	}
	s := r.b[r.i : r.i+n]
	r.i += n
	return s, nil
}

func (r *reader) byte() (byte, error) {
	s, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return s[0], nil
}

func (r *reader) length() (int, error) {
	b, err := r.byte()
	if err != nil {
		return 0, err
	}
	if b == 0x80 {
		return 0, fmt.Errorf("snmpwire: indefinite length: %w", ErrBER)
	}
	if b < 0x80 {
		return int(b), nil
	}
	n := int(b & 0x7f)
	if n == 0 || n > maxBERLengthBytes {
		return 0, fmt.Errorf("snmpwire: invalid length form: %w", ErrBER)
	}
	raw, err := r.take(n)
	if err != nil {
		return 0, err
	}
	var v int
	for _, x := range raw {
		if v > (1<<31-1)>>8 {
			return 0, fmt.Errorf("snmpwire: length overflow: %w", ErrBER)
		}
		v = (v << 8) | int(x)
	}
	if v < 0 {
		return 0, fmt.Errorf("snmpwire: length overflow: %w", ErrBER)
	}
	return v, nil
}

func (r *reader) tlv() (tag byte, content []byte, err error) {
	tag, err = r.byte()
	if err != nil {
		return 0, nil, err
	}
	if tag&0x1f == 0x1f {
		return 0, nil, fmt.Errorf("snmpwire: high-tag-number form: %w", ErrBER)
	}
	n, err := r.length()
	if err != nil {
		return 0, nil, err
	}
	content, err = r.take(n)
	if err != nil {
		return 0, nil, err
	}
	return tag, content, nil
}

func (r *reader) expect(want byte) ([]byte, error) {
	tag, content, err := r.tlv()
	if err != nil {
		return nil, err
	}
	if tag != want {
		return nil, fmt.Errorf("snmpwire: expected tag 0x%02x got 0x%02x: %w", want, tag, ErrBER)
	}
	return content, nil
}

func (r *reader) integer() (int64, error) {
	content, err := r.expect(tagInteger)
	if err != nil {
		return 0, err
	}
	return decodeSigned(content)
}

func (r *reader) int32() (int32, error) {
	v, err := r.integer()
	if err != nil {
		return 0, err
	}
	if v < -1<<31 || v > 1<<31-1 {
		return 0, fmt.Errorf("snmpwire: INTEGER out of int32 range: %w", ErrBER)
	}
	return int32(v), nil
}

func (r *reader) octetString() ([]byte, error) {
	return r.expect(tagOctetString)
}

func (r *reader) oid() (OID, error) {
	content, err := r.expect(tagOID)
	if err != nil {
		return nil, err
	}
	return decodeOID(content)
}

func (r *reader) sequence() ([]byte, error) {
	return r.expect(tagSequence)
}

func wrap(tag byte, content []byte) []byte {
	out := make([]byte, 0, 2+len(content))
	out = append(out, tag)
	out = appendLength(out, len(content))
	out = append(out, content...)
	return out
}

func appendLength(dst []byte, n int) []byte {
	if n < 0 {
		n = 0
	}
	if n < 0x80 {
		return append(dst, byte(n))
	}
	var tmp [4]byte
	k := 0
	v := uint32(n)
	for v > 0 {
		tmp[k] = byte(v)
		v >>= 8
		k++
	}
	dst = append(dst, 0x80|byte(k))
	for i := k - 1; i >= 0; i-- {
		dst = append(dst, tmp[i])
	}
	return dst
}

func encodeInt(v int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	start := 0
	if v < 0 {
		for start < 7 && b[start] == 0xff && b[start+1]&0x80 != 0 {
			start++
		}
	} else {
		for start < 7 && b[start] == 0x00 && b[start+1]&0x80 == 0 {
			start++
		}
	}
	out := make([]byte, 8-start)
	copy(out, b[start:])
	return out
}

func encodeUint(v uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[1:], v)
	start := 1
	for start < 8 && b[start] == 0x00 && b[start+1]&0x80 == 0 {
		start++
	}
	if b[start]&0x80 != 0 {
		start--
	}
	out := make([]byte, 9-start)
	copy(out, b[start:])
	return out
}

func decodeSigned(b []byte) (int64, error) {
	if len(b) == 0 {
		return 0, fmt.Errorf("snmpwire: empty INTEGER: %w", ErrBER)
	}
	if len(b) > 8 {
		return 0, fmt.Errorf("snmpwire: INTEGER too long: %w", ErrBER)
	}
	var v int64
	if b[0]&0x80 != 0 {
		v = -1
	}
	for _, x := range b {
		v = (v << 8) | int64(x)
	}
	return v, nil
}

func decodeUnsigned(b []byte) (uint64, error) {
	if len(b) == 0 {
		return 0, fmt.Errorf("snmpwire: empty unsigned INTEGER: %w", ErrBER)
	}
	if len(b) > 9 {
		return 0, fmt.Errorf("snmpwire: unsigned INTEGER too long: %w", ErrBER)
	}
	if b[0]&0x80 != 0 {
		return 0, fmt.Errorf("snmpwire: unsigned INTEGER is negative: %w", ErrBER)
	}
	var v uint64
	for _, x := range b {
		if v > (^uint64(0))>>8 {
			return 0, fmt.Errorf("snmpwire: unsigned INTEGER overflow: %w", ErrBER)
		}
		v = (v << 8) | uint64(x)
	}
	return v, nil
}

func encodeInteger(v int64) []byte {
	return wrap(tagInteger, encodeInt(v))
}

func encodeOctetString(b []byte) []byte {
	if b == nil {
		b = []byte{}
	}
	return wrap(tagOctetString, b)
}

func encodeNull() []byte {
	return []byte{tagNull, 0}
}

func encodeSequence(content []byte) []byte {
	return wrap(tagSequence, content)
}
