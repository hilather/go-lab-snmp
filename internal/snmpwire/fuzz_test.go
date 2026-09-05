package snmpwire

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzDecode(f *testing.F) {
	for _, g := range goldenCases() {
		b, err := Encode(g.msg)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	if dir := filepath.Join(fuzzRepoRoot(), "testdata", "packets"); dir != "" {
		ents, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range ents {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
					continue
				}
				b, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err == nil {
					f.Add(b)
				}
			}
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x80})
	f.Add([]byte{0x30, 0x81, 0x80})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Add([]byte{0x1f, 0x00})
	f.Add([]byte{0x30, 0x04, 0x02, 0x02, 0x00, 0x80})
	f.Add([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x04, 0x01, 'x'})
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
	f.Add("0.0")
	f.Add("2.999")
	f.Add("2.4294967215")
	f.Add("2.4294967216")
	f.Add("1.40")
	f.Add("3.1")
	f.Add("1.3.6.1.4.1.2021.8.1")
	f.Add("1..3")
	f.Add("foo.1")
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

func FuzzEncode(f *testing.F) {
	f.Add(0, []byte("public"), int32(1), "1.3.6.1.2.1.1.1.0")
	f.Add(1, []byte("private"), int32(-1), ".1.3.6")
	f.Add(2, []byte{}, int32(0), "0.0")
	f.Fuzz(func(t *testing.T, ver int, community []byte, reqID int32, oidStr string) {
		if len(community) > 256 {
			community = community[:256]
		}
		oid, err := ParseOID(oidStr)
		if err != nil {
			return
		}
		v := VersionV2c
		if ver%2 == 0 {
			v = VersionV1
		}
		msg := Message{
			Version:   v,
			Community: append([]byte(nil), community...),
			PDU: &PDU{
				Type:      PDUGet,
				RequestID: reqID,
				VarBinds:  []VarBind{{Name: oid, Value: Null()}},
			},
		}
		b, err := Encode(msg)
		if err != nil {
			return
		}
		m2, err := Decode(b)
		if err != nil {
			t.Fatalf("decode encoded: %v", err)
		}
		b2, err := Encode(m2)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != string(b2) {
			t.Fatal("encode not stable")
		}
	})
}

func FuzzBERInteger(f *testing.F) {
	for _, v := range []int64{0, 1, -1, 127, 128, -128, -129, 256, 1<<31 - 1, -1 << 31} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, v int64) {
		b := wrap(tagInteger, encodeInt(v))
		r := newReader(b)
		got, err := r.integer()
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got != v {
			t.Fatalf("%d -> %d", v, got)
		}
	})
}

func fuzzRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}
