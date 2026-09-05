package audit

import (
	"strings"
	"testing"
)

func TestRingAppendListGet(t *testing.T) {
	r := NewRing(2)
	a := r.Append(Event{ActorID: "a", Result: ResultOK})
	_ = r.Append(Event{ActorID: "b"})
	c := r.Append(Event{ActorID: "c"})
	if r.Len() != 2 {
		t.Fatal(r.Len())
	}
	list := r.List(10)
	if len(list) != 2 || list[0].ActorID != "c" || list[1].ActorID != "b" {
		t.Fatalf("%+v", list)
	}
	if _, ok := r.Get(a.ID); ok {
		t.Fatal("oldest should have fallen off")
	}
	got, ok := r.Get(c.ID)
	if !ok || got.ActorID != "c" {
		t.Fatal(got)
	}
}

func TestRedactSecretPath(t *testing.T) {
	ev := RedactEvent(Event{
		Reason: "ok",
		Diff: []RedactedEntry{{
			Path:   "spec.auth.tokens[0].secretFile",
			Op:     "replace",
			Before: []byte(`"/run/secrets/a"`),
			After:  []byte(`"/run/secrets/b"`),
		}},
	})
	if string(ev.Diff[0].Before) != `"`+redacted+`"` {
		t.Fatalf("%s", ev.Diff[0].Before)
	}
}

func TestRedactJSONKey(t *testing.T) {
	ev := RedactEvent(Event{
		Diff: []RedactedEntry{{
			Path:   "spec.users[0]",
			Op:     "replace",
			Before: []byte(`{"name":"alice","secretFile":"/run/secrets/a"}`),
			After:  []byte(`{"name":"alice","secretFile":"/run/secrets/b"}`),
		}},
	})
	if !strings.Contains(string(ev.Diff[0].After), redacted) {
		t.Fatalf("%s", ev.Diff[0].After)
	}
	if strings.Contains(string(ev.Diff[0].After), "/run/secrets/b") {
		t.Fatalf("secretFile value leaked: %s", ev.Diff[0].After)
	}
}
