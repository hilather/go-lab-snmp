package mibtree

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

// DefaultMaxRepetitions is the local GETBULK cap, matching
// spec.agent.maxRepetitions's default.
const DefaultMaxRepetitions = 100

const (
	violationDuplicateID  = "duplicate_id"
	violationInvalidValue = "invalid_value"
	violationRequired     = "required"
)

// Tree is a lex-ordered instance slice for one named map.
type Tree struct {
	inst           []instance
	maxRepetitions int
}

type instance struct {
	oid       OID
	name      string
	typ       string
	access    string
	value     Value
	valueFrom string
	rng       *model.RangeSpec
	size      *model.RangeSpec
}

// Compile builds a sorted instance tree. Duplicate OIDs are rejected.
// An empty objects list is legal.
func Compile(objects []model.Object) (*Tree, error) {
	t := &Tree{
		inst:           make([]instance, 0, len(objects)),
		maxRepetitions: DefaultMaxRepetitions,
	}
	seen := make(map[string]int, len(objects))
	for i, o := range objects {
		path := fmt.Sprintf("objects[%d]", i)
		oid, err := ParseOID(strings.TrimSpace(o.OID))
		if err != nil {
			code := violationInvalidValue
			if strings.TrimSpace(o.OID) == "" {
				code = violationRequired
			}
			return nil, compileErr(path+".oid", code, err.Error())
		}
		key := oid.String()
		if prev, ok := seen[key]; ok {
			return nil, compileErr(path+".oid", violationDuplicateID,
				fmt.Sprintf("duplicate oid %q (also objects[%d])", key, prev))
		}
		seen[key] = i

		access := strings.TrimSpace(o.Access)
		if access == "" {
			access = model.AccessRead
		}
		switch access {
		case model.AccessRead, model.AccessWrite:
		default:
			return nil, compileErr(path+".access", violationInvalidValue, "access must be read or write")
		}

		val, err := compileValue(o)
		if err != nil {
			field := ".value"
			if strings.TrimSpace(o.ValueFrom) != "" {
				field = ".valueFrom"
			}
			if strings.TrimSpace(o.Type) == "" || !model.KnownObjectType(o.Type) {
				field = ".type"
			}
			return nil, compileErr(path+field, violationInvalidValue, err.Error())
		}

		inst := instance{
			oid:       oid,
			name:      strings.TrimSpace(o.Name),
			typ:       o.Type,
			access:    access,
			value:     val,
			valueFrom: strings.TrimSpace(o.ValueFrom),
		}
		if o.Range != nil {
			if o.Range.Min > o.Range.Max {
				return nil, compileErr(path+".range", violationInvalidValue, "range.min must be <= range.max")
			}
			r := *o.Range
			inst.rng = &r
		}
		if o.Size != nil {
			if o.Size.Min > o.Size.Max {
				return nil, compileErr(path+".size", violationInvalidValue, "size.min must be <= size.max")
			}
			s := *o.Size
			inst.size = &s
		}
		t.inst = append(t.inst, inst)
	}
	sort.Slice(t.inst, func(i, j int) bool {
		return Compare(t.inst[i].oid, t.inst[j].oid) < 0
	})
	return t, nil
}

func compileErr(path, code, msg string) error {
	return domainerr.ValidationFailed(msg,
		domainerr.FieldViolation{Path: path, Code: code, Message: msg})
}

// Len is the number of compiled instances.
func (t *Tree) Len() int {
	if t == nil {
		return 0
	}
	return len(t.inst)
}

// SetMaxRepetitions replaces the local GETBULK cap. n < 1 restores the
// default of 100.
func (t *Tree) SetMaxRepetitions(n int) {
	if t == nil {
		return
	}
	if n < 1 {
		n = DefaultMaxRepetitions
	}
	t.maxRepetitions = n
}

// Get looks up an exact instance. Missing OIDs use the no-compiler
// heuristic: a proper prefix of an instance is noSuchInstance; an
// instance that is a proper prefix of the request (GET under a scalar)
// or no overlap is noSuchObject.
func (t *Tree) Get(oid OID) Result {
	oid = cloneOID(oid)
	if t == nil || len(t.inst) == 0 {
		return Result{OID: oid, Exception: NoSuchObject}
	}
	i := t.searchGE(oid)
	if i < len(t.inst) && Compare(t.inst[i].oid, oid) == 0 {
		return Result{OID: cloneOID(t.inst[i].oid), Value: t.inst[i].value.clone()}
	}
	// Request is a proper prefix of some instance → noSuchInstance.
	// Because the slice is sorted, that instance (if any) is inst[i].
	if i < len(t.inst) && oid.PrefixOf(t.inst[i].oid) {
		return Result{OID: oid, Exception: NoSuchInstance}
	}
	return Result{OID: oid, Exception: NoSuchObject}
}

// GetNext returns the lexicographic successor of oid, or endOfMibView.
func (t *Tree) GetNext(oid OID) Result {
	oid = cloneOID(oid)
	if t == nil || len(t.inst) == 0 {
		return Result{OID: oid, Exception: EndOfMibView}
	}
	i := t.searchGT(oid)
	if i >= len(t.inst) {
		return Result{OID: oid, Exception: EndOfMibView}
	}
	return Result{OID: cloneOID(t.inst[i].oid), Value: t.inst[i].value.clone()}
}

// GetBulk implements RFC 3416 non-repeaters then max-repetitions.
// Negative counts are treated as 0. maxRepetitions is capped at the
// tree local limit (default 100).
func (t *Tree) GetBulk(oids []OID, nonRepeaters, maxRepetitions int) []Result {
	if nonRepeaters < 0 {
		nonRepeaters = 0
	}
	if maxRepetitions < 0 {
		maxRepetitions = 0
	}
	capN := DefaultMaxRepetitions
	if t != nil && t.maxRepetitions > 0 {
		capN = t.maxRepetitions
	}
	if maxRepetitions > capN {
		maxRepetitions = capN
	}
	n := nonRepeaters
	if n > len(oids) {
		n = len(oids)
	}
	r := len(oids) - n
	out := make([]Result, 0, n+maxRepetitions*r)
	for i := 0; i < n; i++ {
		out = append(out, t.GetNext(oids[i]))
	}
	cursors := make([]OID, r)
	for i := 0; i < r; i++ {
		cursors[i] = cloneOID(oids[n+i])
	}
	for rep := 0; rep < maxRepetitions; rep++ {
		for i := 0; i < r; i++ {
			res := t.GetNext(cursors[i])
			out = append(out, res)
			cursors[i] = cloneOID(res.OID)
		}
	}
	return out
}

func (t *Tree) searchGE(oid OID) int {
	return sort.Search(len(t.inst), func(i int) bool {
		return Compare(t.inst[i].oid, oid) >= 0
	})
}

func (t *Tree) searchGT(oid OID) int {
	return sort.Search(len(t.inst), func(i int) bool {
		return Compare(t.inst[i].oid, oid) > 0
	})
}

func (t *Tree) lookup(oid OID) *instance {
	if t == nil {
		return nil
	}
	i := t.searchGE(oid)
	if i < len(t.inst) && Compare(t.inst[i].oid, oid) == 0 {
		return &t.inst[i]
	}
	return nil
}
