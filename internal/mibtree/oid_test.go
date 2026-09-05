package mibtree

import "testing"

func TestParseOID(t *testing.T) {
	got, err := ParseOID("1.3.6")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(OID{1, 3, 6}) {
		t.Fatalf("got %v", got)
	}
	if got.String() != "1.3.6" {
		t.Fatalf("String = %q", got.String())
	}
}

func TestParseOIDRejects(t *testing.T) {
	for _, s := range []string{"", ".1.3.6", "1.03.6", "1..6", "1.3.6.", "iso.3.6", "1.3.-1", " 1.3.6"} {
		if _, err := ParseOID(s); err == nil {
			t.Errorf("ParseOID(%q) succeeded", s)
		}
	}
}

func TestParseOIDMaxArc(t *testing.T) {
	got, err := ParseOID("1.4294967295")
	if err != nil {
		t.Fatal(err)
	}
	if got[1] != 4294967295 {
		t.Fatalf("got %v", got)
	}
	if _, err := ParseOID("1.4294967296"); err == nil {
		t.Fatal("arc above uint32 succeeded")
	}
}

func TestCompareLexOrder(t *testing.T) {
	a := mustOID(t, "1.3.6")
	b := mustOID(t, "1.3.6.1")
	c := mustOID(t, "1.3.10")
	if Compare(a, b) >= 0 {
		t.Fatal("1.3.6 must precede 1.3.6.1")
	}
	if Compare(a, c) >= 0 {
		t.Fatal("1.3.6 must precede 1.3.10 (numeric, not string)")
	}
	if Compare(b, c) >= 0 {
		t.Fatal("1.3.6.1 must precede 1.3.10")
	}
	if Compare(a, a) != 0 {
		t.Fatal("equal")
	}
	if !a.PrefixOf(b) {
		t.Fatal("1.3.6 is a proper prefix of 1.3.6.1")
	}
	if a.PrefixOf(a) || b.PrefixOf(a) {
		t.Fatal("PrefixOf is proper")
	}
}

func FuzzParseOID(f *testing.F) {
	for _, s := range []string{"1.3.6", "1.3.6.1", "0", "10.20.0.3.10.20.0.5.0", ".1.3", "1.03.6", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		oid, err := ParseOID(s)
		if err != nil {
			return
		}
		if oid.String() != s {
			t.Fatalf("round-trip %q -> %q", s, oid.String())
		}
		again, err := ParseOID(oid.String())
		if err != nil || !again.Equal(oid) {
			t.Fatalf("reparse %v: %v", oid, err)
		}
	})
}
