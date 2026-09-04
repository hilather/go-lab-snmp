package snmpwire

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeInt(t *testing.T) {
	cases := []struct {
		v    int64
		want []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7f}},
		{128, []byte{0x00, 0x80}},
		{-1, []byte{0xff}},
		{-128, []byte{0x80}},
		{-129, []byte{0xff, 0x7f}},
		{256, []byte{0x01, 0x00}},
	}
	for _, tc := range cases {
		got := encodeInt(tc.v)
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("encodeInt(%d)=%x want %x", tc.v, got, tc.want)
		}
		back, err := decodeSigned(got)
		if err != nil {
			t.Fatal(err)
		}
		if back != tc.v {
			t.Fatalf("decodeSigned(%x)=%d want %d", got, back, tc.v)
		}
	}
}

func TestEncodeUint(t *testing.T) {
	cases := []struct {
		v    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7f}},
		{128, []byte{0x00, 0x80}},
		{0xffffffff, []byte{0x00, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, tc := range cases {
		got := encodeUint(tc.v)
		if !bytes.Equal(got, tc.want) {
			t.Fatalf("encodeUint(%d)=%x want %x", tc.v, got, tc.want)
		}
		back, err := decodeUnsigned(got)
		if err != nil {
			t.Fatal(err)
		}
		if back != tc.v {
			t.Fatalf("decodeUnsigned(%x)=%d want %d", got, back, tc.v)
		}
	}
}

func TestIndefiniteLengthRejected(t *testing.T) {
	// SEQUENCE, indefinite length
	_, err := Decode([]byte{0x30, 0x80, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrBER) && !errors.Is(err, ErrTruncated) {
		t.Fatalf("err=%v", err)
	}
}

func TestTruncated(t *testing.T) {
	if _, err := Decode(nil); err == nil {
		t.Fatal("expected truncated")
	}
	if _, err := Decode([]byte{0x30}); err == nil {
		t.Fatal("expected truncated")
	}
	if _, err := Decode([]byte{0x30, 0x05, 0x02}); err == nil {
		t.Fatal("expected truncated")
	}
}

func TestLengthOverflow(t *testing.T) {
	// SEQUENCE claiming 2^24 bytes
	b := []byte{0x30, 0x83, 0x10, 0x00, 0x00}
	if _, err := Decode(b); err == nil {
		t.Fatal("expected error")
	}
}
