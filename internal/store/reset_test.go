package store

import (
	"testing"

	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func TestResetEphemeralDropsOverlayTrapsQueries(t *testing.T) {
	ov := NewOverlay()
	ov.Set("m", "1.3.6", mibtree.Value{Type: model.TypeInteger, Signed: 2})
	traps := NewTrapRing(TrapPolicy{MaxMessages: 8, MaxBytes: 1024})
	if _, err := traps.Insert(TrapRecord{Version: "v2c", PDUType: "trap"}); err != nil {
		t.Fatal(err)
	}
	q := NewQueryRing(8)
	q.Insert(Query{Type: "get", Identity: "public", Decision: "ok"})

	beforeOV := ov.Generation()
	beforeTrap := traps.Generation()
	ResetEphemeral(ov, traps, q)

	if _, ok := ov.Get("m", "1.3.6"); ok {
		t.Fatal("overlay")
	}
	if ov.Generation() <= beforeOV {
		t.Fatal("overlay generation")
	}
	if traps.Stats().Messages != 0 {
		t.Fatal("traps")
	}
	if traps.Generation() <= beforeTrap {
		t.Fatal("trap generation")
	}
	if q.Len() != 0 {
		t.Fatal("queries")
	}
}
