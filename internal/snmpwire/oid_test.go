package snmpwire

import (
	"errors"
	"testing"
)

func TestParseOID(t *testing.T) {
	cases := []struct {
		in   string
		want OID
	}{
		{"1.3.6.1.2.1.1.1.0", OID{1, 3, 6, 1, 2, 1, 1, 1, 0}},
		{".1.3.6.1.2.1.1.1.0", OID{1, 3, 6, 1, 2, 1, 1, 1, 0}},
		{"0.0", OID{0, 0}},
		{"2.999", OID{2, 999}},
		{"2.4294967215", OID{2, 4294967215}},
	}
	for _, tc := range cases {
		got, err := ParseOID(tc.in)
		if err != nil {
			t.Fatalf("ParseOID(%q): %v", tc.in, err)
		}
		if !got.Equal(tc.want) {
			t.Fatalf("ParseOID(%q)=%v want %v", tc.in, got, tc.want)
		}
		if tc.in[0] != '.' && got.String() != tc.in {
			t.Fatalf("String()=%q want %q", got.String(), tc.in)
		}
	}
}

func TestParseOIDRejects(t *testing.T) {
	bads := []string{"", ".", "1", "1.", ".1.", "1..2", "foo.1", "3.1", "1.40", "1.3.x", "2.4294967216"}
	for _, s := range bads {
		if _, err := ParseOID(s); err == nil {
			t.Fatalf("ParseOID(%q) succeeded", s)
		} else if !errors.Is(err, ErrOID) {
			t.Fatalf("ParseOID(%q) err=%v, want ErrOID", s, err)
		}
	}
}

func TestOIDRoundTrip(t *testing.T) {
	oids := []OID{
		{1, 3, 6, 1, 2, 1, 1, 1, 0},
		{0, 0},
		{2, 999, 1},
		{1, 3, 6, 1, 4, 1, 2021, 8, 1},
		{2, 4294967215},
	}
	for _, oid := range oids {
		b, err := encodeOID(oid)
		if err != nil {
			t.Fatal(err)
		}
		r := newReader(b)
		got, err := r.oid()
		if err != nil {
			t.Fatal(err)
		}
		if !got.Equal(oid) {
			t.Fatalf("%v -> %v", oid, got)
		}
	}
}

func TestOID1_3EncodedAs2b(t *testing.T) {
	b, err := encodeOID(OID{1, 3, 6, 1, 2, 1, 1, 1, 0})
	if err != nil {
		t.Fatal(err)
	}
	if b[0] != tagOID {
		t.Fatalf("tag %02x", b[0])
	}
	if b[2] != 0x2b {
		t.Fatalf("first content octet %02x, want 2b", b[2])
	}
}
