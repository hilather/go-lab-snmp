package snmpwire

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func sampleGet() Message {
	return Message{
		Version:   VersionV2c,
		Community: []byte("public"),
		PDU: &PDU{
			Type:      PDUGet,
			RequestID: 1,
			VarBinds:  []VarBind{vb(sysDescr(), Null())},
		},
	}
}

func TestWriteTCPNoPrefix(t *testing.T) {
	encoded := mustEncode(t, sampleGet())
	if encoded[0] != tagSequence {
		t.Fatalf("encode starts with 0x%02x, want 0x30", encoded[0])
	}
	var buf bytes.Buffer
	if err := WriteTCP(&buf, encoded); err != nil {
		t.Fatal(err)
	}
	got := buf.Bytes()
	if got[0] != tagSequence {
		t.Fatalf("WriteTCP starts with 0x%02x, want 0x30", got[0])
	}
	if len(got) >= 4 && got[0] == 0 && got[1] == 0 && got[2] == 0 {
		t.Fatal("WriteTCP prepended a 32-bit length prefix")
	}
	if !bytes.Equal(got, encoded) {
		t.Fatalf("WriteTCP mutated message\ngot %x\nwant %x", got, encoded)
	}
}

func TestReadTCPFramedGet(t *testing.T) {
	encoded := mustEncode(t, sampleGet())
	if encoded[0] != tagSequence {
		t.Fatalf("framed Get starts with 0x%02x, want 0x30", encoded[0])
	}
	if encoded[0] == 0 {
		t.Fatal("32-bit length prefix is not RFC 3430")
	}

	var buf bytes.Buffer
	if err := WriteTCP(&buf, encoded); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTCP(&buf, DefaultMaxMessageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != tagSequence {
		t.Fatalf("ReadTCP starts with 0x%02x, want 0x30", got[0])
	}
	if !bytes.Equal(got, encoded) {
		t.Fatalf("ReadTCP %x want %x", got, encoded)
	}
	msg, err := DecodeMax(got, DefaultMaxMessageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Version != VersionV2c || msg.PDU == nil || msg.PDU.Type != PDUGet {
		t.Fatalf("decoded %+v", msg)
	}
}

func TestReadTCPErrors(t *testing.T) {
	encoded := mustEncode(t, sampleGet())
	prefix32 := append([]byte{0, 0, 0, byte(len(encoded))}, encoded...)
	cases := []struct {
		name string
		in   []byte
		max  int64
		want error
	}{
		{"empty", nil, 0, ErrTruncated},
		{"truncated-tag", []byte{}, 0, ErrTruncated},
		{"truncated-length", []byte{0x30}, 0, ErrTruncated},
		{"truncated-long-length", []byte{0x30, 0x81}, 0, ErrTruncated},
		{"truncated-content", []byte{0x30, 0x05, 0x02, 0x01}, 0, ErrTruncated},
		{"indefinite", []byte{0x30, 0x80, 0x00, 0x00}, 0, ErrBER},
		{"wrong-tag", []byte{0x02, 0x01, 0x00}, 0, ErrBER},
		{"high-tag", []byte{0x1f, 0x00}, 0, ErrBER},
		{"prefix-32", prefix32, 0, ErrBER},
		{"oversize-length", []byte{0x30, 0x82, 0x01, 0x00}, 16, ErrTooLarge},
		{"oversize-header", []byte{0x30, 0x00}, 1, ErrTooLarge},
		{"invalid-length-form", []byte{0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00}, 0, ErrBER},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadTCP(bytes.NewReader(tc.in), tc.max)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v, want %v", err, tc.want)
			}
		})
	}
}

func TestReadTCPEmptySequence(t *testing.T) {
	got, err := ReadTCP(bytes.NewReader([]byte{0x30, 0x00}), DefaultMaxMessageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0x30, 0x00}) {
		t.Fatalf("got %x", got)
	}
}

func TestReadTCPLeavesRemainder(t *testing.T) {
	encoded := mustEncode(t, sampleGet())
	r := bytes.NewReader(append(append([]byte{}, encoded...), 0xff, 0xee))
	got, err := ReadTCP(r, DefaultMaxMessageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, encoded) {
		t.Fatalf("got %x want %x", got, encoded)
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, []byte{0xff, 0xee}) {
		t.Fatalf("remainder %x", rest)
	}
}

func TestReadTCPConcatenated(t *testing.T) {
	a := mustEncode(t, sampleGet())
	b := mustEncode(t, Message{
		Version:   VersionV1,
		Community: []byte("public"),
		PDU: &PDU{
			Type:      PDUGet,
			RequestID: 2,
			VarBinds:  []VarBind{vb(sysDescr(), Null())},
		},
	})
	r := bytes.NewReader(append(append([]byte{}, a...), b...))
	gotA, err := ReadTCP(r, DefaultMaxMessageBytes)
	if err != nil {
		t.Fatal(err)
	}
	gotB, err := ReadTCP(r, DefaultMaxMessageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotA, a) || !bytes.Equal(gotB, b) {
		t.Fatalf("a=%x want %x\nb=%x want %x", gotA, a, gotB, b)
	}
}

func TestReadTCPLongFormLength(t *testing.T) {
	encoded := mustEncode(t, sampleGet())
	if encoded[1] >= 0x80 {
		t.Fatalf("expected short-form length, got %x", encoded[:4])
	}
	long := []byte{encoded[0], 0x81, encoded[1]}
	long = append(long, encoded[2:]...)
	got, err := ReadTCP(bytes.NewReader(long), DefaultMaxMessageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, long) {
		t.Fatalf("got %x want %x", got, long)
	}
	if _, err := DecodeMax(got, DefaultMaxMessageBytes); err != nil {
		t.Fatal(err)
	}
}

func TestReadTCPByteAtATime(t *testing.T) {
	encoded := mustEncode(t, sampleGet())
	got, err := ReadTCP(&oneByteReader{b: encoded}, DefaultMaxMessageBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, encoded) {
		t.Fatalf("got %x want %x", got, encoded)
	}
}

func TestReadTCPWriteTCPRoundTrip(t *testing.T) {
	encoded := mustEncode(t, sampleGet())
	var buf bytes.Buffer
	if err := WriteTCP(&buf, encoded); err != nil {
		t.Fatal(err)
	}
	if err := WriteTCP(&buf, encoded); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		got, err := ReadTCP(&buf, 0)
		if err != nil {
			t.Fatal(err)
		}
		if got[0] != tagSequence {
			t.Fatalf("frame %d starts with 0x%02x", i, got[0])
		}
		if !bytes.Equal(got, encoded) {
			t.Fatalf("frame %d %x", i, got)
		}
	}
}

type oneByteReader struct {
	b []byte
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = r.b[0]
	r.b = r.b[1:]
	return 1, nil
}
