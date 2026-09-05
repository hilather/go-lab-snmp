package mibtree

import (
	"errors"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func TestCheckSetAccessAndUptime(t *testing.T) {
	tree := mustCompileFile(t, "system-if.yaml")
	sysDescr := oid(1, 3, 6, 1, 2, 1, 1, 1, 0)
	sysUpTime := oid(1, 3, 6, 1, 2, 1, 1, 3, 0)

	err := tree.CheckSet(sysDescr, Value{Type: model.TypeOctetString, Bytes: []byte("x")})
	if !errors.Is(err, ErrNotWritable) {
		t.Fatalf("read leaf: %v", err)
	}
	err = tree.CheckSet(sysUpTime, Value{Type: model.TypeTimeTicks, Unsigned: 1})
	if !errors.Is(err, ErrNotWritable) {
		t.Fatalf("uptime: %v", err)
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeNotWritable {
		t.Fatalf("domain = %v", err)
	}

	err = tree.CheckSet(oid(1, 2, 3, 4), Value{Type: model.TypeInteger, Signed: 1})
	if !errors.Is(err, ErrNotWritable) {
		t.Fatalf("missing: %v", err)
	}
}

func TestCheckSetTypeRangeSize(t *testing.T) {
	tree := mustCompileFile(t, "system-if.yaml")
	ifOper := oid(1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1)

	if err := tree.CheckSet(ifOper, Value{Type: model.TypeInteger, Signed: 2}); err != nil {
		t.Fatalf("in-range write: %v", err)
	}
	err := tree.CheckSet(ifOper, Value{Type: model.TypeOctetString, Bytes: []byte("up")})
	if !errors.Is(err, ErrWrongType) {
		t.Fatalf("wrong type: %v", err)
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeWrongType {
		t.Fatalf("domain wrongType = %v", err)
	}
	err = tree.CheckSet(ifOper, Value{Type: model.TypeInteger, Signed: 8})
	if !errors.Is(err, ErrWrongValue) {
		t.Fatalf("range: %v", err)
	}

	sysContact := oid(1, 3, 6, 1, 2, 1, 1, 4, 0)
	if err := tree.CheckSet(sysContact, Value{Type: model.TypeOctetString, Bytes: []byte("ok")}); err != nil {
		t.Fatalf("size ok: %v", err)
	}
	long := make([]byte, 65)
	err = tree.CheckSet(sysContact, Value{Type: model.TypeOctetString, Bytes: long})
	if !errors.Is(err, ErrWrongLength) {
		t.Fatalf("size: %v", err)
	}

	gauge := oid(1, 3, 6, 1, 4, 1, 99999, 1, 0)
	if err := tree.CheckSet(gauge, Value{Type: model.TypeGauge32, Unsigned: 50}); err != nil {
		t.Fatalf("gauge: %v", err)
	}
	coerced := Value{Type: model.TypeUnsigned32, Unsigned: 50}
	if err := tree.CheckSetCoerce(gauge, &coerced); err != nil {
		t.Fatalf("coerce unsigned→gauge: %v", err)
	}
	if coerced.Type != model.TypeGauge32 {
		t.Fatalf("coerced type %s", coerced.Type)
	}
	if err := tree.CheckSet(gauge, Value{Type: model.TypeGauge32, Unsigned: 101}); !errors.Is(err, ErrWrongValue) {
		t.Fatalf("gauge range: %v", err)
	}

	opaque := oid(1, 3, 6, 1, 4, 1, 99999, 3, 0)
	if err := tree.CheckSet(opaque, Value{Type: model.TypeOpaque, Bytes: []byte("ok")}); err != nil {
		t.Fatalf("opaque: %v", err)
	}
	if err := tree.CheckSet(opaque, Value{Type: model.TypeOpaque, Bytes: []byte("toolongxx")}); !errors.Is(err, ErrWrongLength) {
		t.Fatalf("opaque size: %v", err)
	}
}

func TestCheckSetDoesNotWrite(t *testing.T) {
	tree := mustCompileFile(t, "system-if.yaml")
	leaf := oid(1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1)
	before := tree.Get(leaf)
	if err := tree.CheckSet(leaf, Value{Type: model.TypeInteger, Signed: 2}); err != nil {
		t.Fatal(err)
	}
	after := tree.Get(leaf)
	if after.Value.Signed != before.Value.Signed {
		t.Fatalf("CheckSet mutated bootstrap %d -> %d", before.Value.Signed, after.Value.Signed)
	}
}

func TestCheckSetIPAddressLength(t *testing.T) {
	leaf := oid(1, 3, 6, 1, 1)
	tree, err := Compile([]model.Object{
		{OID: leaf.String(), Type: model.TypeIPAddress, Access: model.AccessWrite, Value: "10.0.0.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.CheckSet(leaf, Value{Type: model.TypeIPAddress, Bytes: []byte{10, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := tree.CheckSet(leaf, Value{Type: model.TypeIPAddress, Bytes: []byte{1, 2}}); !errors.Is(err, ErrWrongLength) {
		t.Fatalf("short ip: %v", err)
	}
}
