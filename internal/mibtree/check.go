package mibtree

import (
	"errors"
	"math"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

// SetError is a CheckSet failure. Overlay is not written.
type SetError struct {
	Kind string
	OID  OID
}

func (e *SetError) Error() string {
	if e == nil {
		return ""
	}
	if e.Kind == "" {
		return "set error"
	}
	return e.Kind
}

func (e *SetError) Is(target error) bool {
	t, ok := target.(*SetError)
	return ok && e != nil && t != nil && e.Kind == t.Kind
}

func (e *SetError) Unwrap() error {
	if e == nil {
		return nil
	}
	switch e.Kind {
	case "notWritable":
		return domainerr.New(domainerr.CodeNotWritable, e.Kind)
	case "wrongType":
		return domainerr.New(domainerr.CodeWrongType, e.Kind)
	default:
		return domainerr.New(domainerr.CodeValidationFailed, e.Kind)
	}
}

var (
	// ErrNotWritable is returned for read-only, valueFrom, and missing leaves.
	ErrNotWritable = &SetError{Kind: "notWritable"}
	// ErrWrongType is a type mismatch against the compiled leaf.
	ErrWrongType = &SetError{Kind: "wrongType"}
	// ErrWrongLength is an octet size mismatch.
	ErrWrongLength = &SetError{Kind: "wrongLength"}
	// ErrWrongValue is a range or integer-domain mismatch.
	ErrWrongValue = &SetError{Kind: "wrongValue"}
)

// CheckSet validates access, type, and range/size. It does not apply an
// overlay. valueFrom: uptime is never writable.
func (t *Tree) CheckSet(oid OID, v Value) error {
	inst := t.lookup(oid)
	if inst == nil {
		return &SetError{Kind: ErrNotWritable.Kind, OID: cloneOID(oid)}
	}
	if inst.valueFrom == model.ValueFromUptime || inst.access != model.AccessWrite {
		return &SetError{Kind: ErrNotWritable.Kind, OID: cloneOID(inst.oid)}
	}
	if v.Type != inst.typ {
		return &SetError{Kind: ErrWrongType.Kind, OID: cloneOID(inst.oid)}
	}
	switch inst.typ {
	case model.TypeInteger:
		if v.Signed < math.MinInt32 || v.Signed > math.MaxInt32 {
			return &SetError{Kind: ErrWrongValue.Kind, OID: cloneOID(inst.oid)}
		}
		if inst.rng != nil && (v.Signed < inst.rng.Min || v.Signed > inst.rng.Max) {
			return &SetError{Kind: ErrWrongValue.Kind, OID: cloneOID(inst.oid)}
		}
	case model.TypeCounter32, model.TypeGauge32, model.TypeUnsigned32, model.TypeTimeTicks:
		if v.Unsigned > math.MaxUint32 {
			return &SetError{Kind: ErrWrongValue.Kind, OID: cloneOID(inst.oid)}
		}
		if inst.rng != nil {
			min := inst.rng.Min
			max := inst.rng.Max
			if min < 0 {
				min = 0
			}
			if v.Unsigned < uint64(min) || (max >= 0 && v.Unsigned > uint64(max)) {
				return &SetError{Kind: ErrWrongValue.Kind, OID: cloneOID(inst.oid)}
			}
		}
	case model.TypeCounter64:
		if inst.rng != nil {
			min := inst.rng.Min
			max := inst.rng.Max
			if min < 0 {
				min = 0
			}
			if v.Unsigned < uint64(min) || (max >= 0 && v.Unsigned > uint64(max)) {
				return &SetError{Kind: ErrWrongValue.Kind, OID: cloneOID(inst.oid)}
			}
		}
	case model.TypeOctetString, model.TypeOpaque:
		n := int64(len(v.Bytes))
		if inst.size != nil && (n < inst.size.Min || n > inst.size.Max) {
			return &SetError{Kind: ErrWrongLength.Kind, OID: cloneOID(inst.oid)}
		}
	case model.TypeIPAddress:
		if len(v.Bytes) != 4 {
			return &SetError{Kind: ErrWrongLength.Kind, OID: cloneOID(inst.oid)}
		}
	case model.TypeObjectIdentifier:
		// any OID (including empty) is a well-typed objectIdentifier
	case model.TypeNull:
	default:
		return &SetError{Kind: ErrWrongType.Kind, OID: cloneOID(inst.oid)}
	}
	return nil
}

// IsNotWritable reports whether err is a notWritable CheckSet failure.
func IsNotWritable(err error) bool {
	return errors.Is(err, ErrNotWritable)
}

// CheckSetCoerce is CheckSet plus the gauge32↔unsigned32 alias used by
// SNMP SET and REST/MCP oids:set. On success val.Type may be rewritten
// to the compiled leaf type.
func (t *Tree) CheckSetCoerce(oid OID, val *Value) error {
	if val == nil {
		return ErrWrongType
	}
	err := t.CheckSet(oid, *val)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrWrongType) {
		return err
	}
	switch val.Type {
	case model.TypeGauge32:
		val.Type = model.TypeUnsigned32
		return t.CheckSet(oid, *val)
	case model.TypeUnsigned32:
		val.Type = model.TypeGauge32
		return t.CheckSet(oid, *val)
	default:
		return err
	}
}
