package snmpwire

import "testing"

func FuzzDecode(f *testing.F) {
	for _, g := range goldenCases() {
		b, err := Encode(g.msg)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x80})
	f.Add(make([]byte, 47))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2048 {
			data = data[:2048]
		}
		m, err := Decode(data)
		if err != nil {
			return
		}
		b, err := Encode(m)
		if err != nil {
			t.Fatalf("encode after decode: %v", err)
		}
		m2, err := Decode(b)
		if err != nil {
			t.Fatalf("decode after encode: %v", err)
		}
		b2, err := Encode(m2)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != string(b2) {
			t.Fatalf("encode not stable")
		}
	})
}

func FuzzParseOID(f *testing.F) {
	f.Add("1.3.6.1.2.1.1.1.0")
	f.Add(".1.3.6")
	f.Add("")
	f.Add("1")
	f.Add("2.999")
	f.Add("2.4294967215")
	f.Add("2.4294967216")
	f.Fuzz(func(t *testing.T, s string) {
		oid, err := ParseOID(s)
		if err != nil {
			return
		}
		b, err := encodeOID(oid)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		r := newReader(b)
		got, err := r.oid()
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !got.Equal(oid) {
			t.Fatalf("%v vs %v", got, oid)
		}
	})
}
