package store

import "testing"

func TestQueryRingEvictsOldest(t *testing.T) {
	r := NewQueryRing(2)
	r.Insert(Query{Type: "get", Identity: "public", Decision: "ok"})
	r.Insert(Query{Type: "set", Identity: "private", Decision: "ok"})
	r.Insert(Query{Type: "getnext", Identity: "public", Decision: "ok"})
	got := r.List()
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0].Type != "set" || got[1].Type != "getnext" {
		t.Fatalf("%+v", got)
	}
}

func TestQueryRingDefaultCap(t *testing.T) {
	r := NewQueryRing(0)
	if r.cap != DefaultQueryRing {
		t.Fatalf("cap=%d", r.cap)
	}
}
