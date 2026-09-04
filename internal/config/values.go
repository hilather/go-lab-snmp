package config

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func coerceObjectValues(st *model.State) []domainerr.FieldViolation {
	if st == nil {
		return nil
	}
	var vs []domainerr.FieldViolation
	for i := range st.Spec.Maps {
		for j := range st.Spec.Maps[i].Objects {
			o := &st.Spec.Maps[i].Objects[j]
			if o.Value == nil {
				continue
			}
			path := fmt.Sprintf("spec.maps[%d].objects[%d].value", i, j)
			v, viol, ok := coerceValueForType(o.Type, o.Value, path)
			if !ok {
				vs = append(vs, viol)
				continue
			}
			o.Value = v
		}
	}
	return vs
}

func coerceValueForType(typ string, v any, path string) (any, domainerr.FieldViolation, bool) {
	switch typ {
	case model.TypeInteger:
		n, err := asInt64(v)
		if err != nil || n < math.MinInt32 || n > math.MaxInt32 {
			return nil, valueTypeViolation(path, "integer value must fit Integer32"), false
		}
		return n, domainerr.FieldViolation{}, true
	case model.TypeCounter32, model.TypeGauge32, model.TypeUnsigned32, model.TypeTimeTicks:
		n, err := asUint64(v)
		if err != nil || n > math.MaxUint32 {
			return nil, valueTypeViolation(path, typ+" value must fit Unsigned32"), false
		}
		return uint32(n), domainerr.FieldViolation{}, true
	case model.TypeCounter64:
		n, err := asUint64(v)
		if err != nil {
			return nil, valueTypeViolation(path, "counter64 value must fit Unsigned64"), false
		}
		return n, domainerr.FieldViolation{}, true
	default:
		if _, ok := v.(json.Number); ok {
			return nil, valueTypeViolation(path, "numeric value is not valid for this type"), false
		}
		return v, domainerr.FieldViolation{}, true
	}
}

func valueTypeViolation(path, msg string) domainerr.FieldViolation {
	return domainerr.FieldViolation{Path: path, Code: violationInvalidValue, Message: msg}
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
	default:
		return 0, strconv.ErrSyntax
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
