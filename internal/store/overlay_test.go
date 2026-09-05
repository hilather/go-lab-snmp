package store

import (
	"testing"

	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func TestOverlaySetAllOneGeneration(t *testing.T) {
	o := NewOverlay()
	if o.Generation() != 0 {
		t.Fatalf("gen=%d", o.Generation())
	}
	o.SetAll("public-if", []Pair{
		{OID: "1.3.6.1.2.1.1.1.0", Value: mibtree.Value{Type: model.TypeOctetString, Bytes: []byte("a")}},
		{OID: "1.3.6.1.2.1.2.2.1.8.1", Value: mibtree.Value{Type: model.TypeInteger, Signed: 2}},
	})
	if o.Generation() != 1 {
		t.Fatalf("gen=%d want 1", o.Generation())
	}
	v, ok := o.Get("public-if", "1.3.6.1.2.1.1.1.0")
	if !ok || string(v.Bytes) != "a" {
		t.Fatalf("get sysDescr: ok=%v %+v", ok, v)
	}
	v, ok = o.Get("private-if", "1.3.6.1.2.1.1.1.0")
	if ok {
		t.Fatalf("isolation leak: %+v", v)
	}
}

func TestOverlaySetClonesBytes(t *testing.T) {
	o := NewOverlay()
	b := []byte("hello")
	o.Set("m", "1.2.3", mibtree.Value{Type: model.TypeOctetString, Bytes: b})
	b[0] = 'x'
	v, ok := o.Get("m", "1.2.3")
	if !ok || string(v.Bytes) != "hello" {
		t.Fatalf("alias: ok=%v %q", ok, v.Bytes)
	}
}

func TestOverlayClearBumpsGeneration(t *testing.T) {
	o := NewOverlay()
	o.Set("m", "1.3", mibtree.Value{Type: model.TypeInteger, Signed: 1})
	o.Clear()
	if o.Generation() != 2 {
		t.Fatalf("gen=%d want 2", o.Generation())
	}
	if _, ok := o.Get("m", "1.3"); ok {
		t.Fatal("cleared value still present")
	}
}
