package mibtree

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-snmp/internal/model"
)

// Exception is a v2c/v3 varbind exception. v1 maps these at the PDU layer.
type Exception int

const (
	// NoException means the varbind carries a value.
	NoException Exception = iota
	// NoSuchObject is RFC 3416 noSuchObject.
	NoSuchObject
	// NoSuchInstance is RFC 3416 noSuchInstance.
	NoSuchInstance
	// EndOfMibView is RFC 3416 endOfMibView.
	EndOfMibView
)

func (e Exception) String() string {
	switch e {
	case NoSuchObject:
		return "noSuchObject"
	case NoSuchInstance:
		return "noSuchInstance"
	case EndOfMibView:
		return "endOfMibView"
	default:
		return "noError"
	}
}

// Value is a typed instance payload. Types are YAML camelCase names from
// model (integer, octetString, …). Overlay apply is not stored here.
type Value struct {
	Type      string
	Signed    int64
	Unsigned  uint64
	Bytes     []byte
	OID       OID
	ValueFrom string
}

// Result is one Get / GetNext / GetBulk binding.
type Result struct {
	OID       OID
	Value     Value
	Exception Exception
}

func (v Value) clone() Value {
	out := v
	if v.Bytes != nil {
		out.Bytes = append([]byte(nil), v.Bytes...)
	}
	out.OID = cloneOID(v.OID)
	return out
}

func compileValue(o model.Object) (Value, error) {
	if vf := strings.TrimSpace(o.ValueFrom); vf != "" {
		if vf != model.ValueFromUptime {
			return Value{}, fmt.Errorf("valueFrom must be uptime")
		}
		if o.Type != model.TypeTimeTicks {
			return Value{}, fmt.Errorf("valueFrom uptime requires type timeTicks")
		}
		if o.Access != "" && o.Access != model.AccessRead {
			return Value{}, fmt.Errorf("valueFrom uptime requires access read")
		}
		if o.Value != nil {
			return Value{}, fmt.Errorf("value must be omitted when valueFrom is set")
		}
		return Value{Type: model.TypeTimeTicks, ValueFrom: model.ValueFromUptime}, nil
	}
	if o.Value == nil && o.Type != model.TypeNull {
		return Value{}, fmt.Errorf("value is required unless valueFrom is set")
	}
	switch o.Type {
	case model.TypeInteger:
		n, err := asInt64(o.Value)
		if err != nil || n < math.MinInt32 || n > math.MaxInt32 {
			return Value{}, fmt.Errorf("integer value must fit Integer32")
		}
		return Value{Type: o.Type, Signed: n}, nil
	case model.TypeCounter32, model.TypeGauge32, model.TypeUnsigned32, model.TypeTimeTicks:
		n, err := asUint64(o.Value)
		if err != nil || n > math.MaxUint32 {
			return Value{}, fmt.Errorf("%s value must fit Unsigned32", o.Type)
		}
		return Value{Type: o.Type, Unsigned: n}, nil
	case model.TypeCounter64:
		n, err := asUint64(o.Value)
		if err != nil {
			return Value{}, fmt.Errorf("counter64 value must fit Unsigned64")
		}
		return Value{Type: o.Type, Unsigned: n}, nil
	case model.TypeOctetString, model.TypeOpaque:
		b, err := asBytes(o.Value)
		if err != nil {
			return Value{}, err
		}
		return Value{Type: o.Type, Bytes: b}, nil
	case model.TypeIPAddress:
		b, err := asIP(o.Value)
		if err != nil {
			return Value{}, err
		}
		return Value{Type: o.Type, Bytes: b}, nil
	case model.TypeObjectIdentifier:
		oid, err := asCompiledOID(o.Value)
		if err != nil {
			return Value{}, err
		}
		return Value{Type: o.Type, OID: oid}, nil
	case model.TypeNull:
		return Value{Type: o.Type}, nil
	default:
		if strings.TrimSpace(o.Type) == "" {
			return Value{}, fmt.Errorf("type is required")
		}
		return Value{}, fmt.Errorf("type must be a 1.0 SNMP varbind type")
	}
}

func asInt64(v any) (int64, error) {
	switch n := v.(type) {
	case json.Number:
		s := n.String()
		if !integerString(s) {
			return 0, strconv.ErrSyntax
		}
		return strconv.ParseInt(s, 10, 64)
	case int:
		return int64(n), nil
	case int8:
		return int64(n), nil
	case int16:
		return int64(n), nil
	case int32:
		return int64(n), nil
	case int64:
		return n, nil
	case uint:
		if uint64(n) > math.MaxInt64 {
			return 0, strconv.ErrRange
		}
		return int64(n), nil
	case uint32:
		return int64(n), nil
	case uint64:
		if n > math.MaxInt64 {
			return 0, strconv.ErrRange
		}
		return int64(n), nil
	case float64:
		if n != math.Trunc(n) || n < math.MinInt64 || n > math.MaxInt64 {
			return 0, strconv.ErrSyntax
		}
		return int64(n), nil
	default:
		return 0, strconv.ErrSyntax
	}
}

func asUint64(v any) (uint64, error) {
	switch n := v.(type) {
	case json.Number:
		s := n.String()
		if !integerString(s) || strings.HasPrefix(s, "-") {
			return 0, strconv.ErrSyntax
		}
		return strconv.ParseUint(s, 10, 64)
	case uint:
		return uint64(n), nil
	case uint8:
		return uint64(n), nil
	case uint16:
		return uint64(n), nil
	case uint32:
		return uint64(n), nil
	case uint64:
		return n, nil
	case int:
		if n < 0 {
			return 0, strconv.ErrRange
		}
		return uint64(n), nil
	case int32:
		if n < 0 {
			return 0, strconv.ErrRange
		}
		return uint64(n), nil
	case int64:
		if n < 0 {
			return 0, strconv.ErrRange
		}
		return uint64(n), nil
	case float64:
		if n < 0 || n != math.Trunc(n) || n > math.MaxUint64 {
			return 0, strconv.ErrRange
		}
		return uint64(n), nil
	default:
		return 0, strconv.ErrSyntax
	}
}

func asBytes(v any) ([]byte, error) {
	switch b := v.(type) {
	case string:
		return []byte(b), nil
	case []byte:
		out := make([]byte, len(b))
		copy(out, b)
		return out, nil
	default:
		return nil, fmt.Errorf("value must be an octet string")
	}
}

func asIP(v any) ([]byte, error) {
	switch b := v.(type) {
	case string:
		ip := net.ParseIP(b)
		if ip == nil {
			return nil, fmt.Errorf("value must be an IPv4 address")
		}
		v4 := ip.To4()
		if v4 == nil {
			return nil, fmt.Errorf("value must be an IPv4 address")
		}
		out := make([]byte, 4)
		copy(out, v4)
		return out, nil
	case []byte:
		if len(b) != 4 {
			return nil, fmt.Errorf("ipAddress value must be 4 octets")
		}
		out := make([]byte, 4)
		copy(out, b)
		return out, nil
	default:
		return nil, fmt.Errorf("value must be an IPv4 address")
	}
}

func asCompiledOID(v any) (OID, error) {
	switch x := v.(type) {
	case string:
		return ParseOID(x)
	case OID:
		return cloneOID(x), nil
	case []uint32:
		return cloneOID(OID(x)), nil
	default:
		return nil, fmt.Errorf("value must be an object identifier")
	}
}

func integerString(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' {
		s = s[1:]
		if s == "" {
			return false
		}
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
