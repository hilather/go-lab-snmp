package snmpwire

import (
	"bytes"
	"errors"
	"testing"
)

func sysDescr() OID { return OID{1, 3, 6, 1, 2, 1, 1, 1, 0} }

func vb(oid OID, v Value) VarBind { return VarBind{Name: oid, Value: v} }

func mustEncode(t *testing.T, m Message) []byte {
	t.Helper()
	b, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCommunityRoundTrip(t *testing.T) {
	cases := []Message{
		{
			Version:   VersionV1,
			Community: []byte("public"),
			PDU: &PDU{
				Type:      PDUGet,
				RequestID: 7,
				VarBinds:  []VarBind{vb(sysDescr(), Null())},
			},
		},
		{
			Version:   VersionV1,
			Community: []byte("public"),
			PDU: &PDU{
				Type:      PDUGetNext,
				RequestID: 8,
				VarBinds:  []VarBind{vb(OID{1, 3, 6, 1, 2, 1}, Null())},
			},
		},
		{
			Version:   VersionV1,
			Community: []byte("private"),
			PDU: &PDU{
				Type:      PDUSet,
				RequestID: 9,
				VarBinds:  []VarBind{vb(sysDescr(), OctetString([]byte("lab")))},
			},
		},
		{
			Version:   VersionV1,
			Community: []byte("public"),
			PDU: &PDU{
				Type:        PDUResponse,
				RequestID:   7,
				ErrorStatus: ErrorStatusNoSuchName,
				ErrorIndex:  1,
				VarBinds:    []VarBind{vb(sysDescr(), Null())},
			},
		},
		{
			Version:   VersionV1,
			Community: []byte("public"),
			PDU: &PDU{
				Type:         PDUTrapV1,
				Enterprise:   OID{1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1},
				AgentAddr:    [4]byte{127, 0, 0, 1},
				GenericTrap:  TrapColdStart,
				SpecificTrap: 0,
				Timestamp:    12345,
				VarBinds:     []VarBind{vb(OID{1, 3, 6, 1, 2, 1, 1, 3, 0}, TimeTicksVal(12345))},
			},
		},
		{
			Version:   VersionV2c,
			Community: []byte("public"),
			PDU: &PDU{
				Type:           PDUGetBulk,
				RequestID:      42,
				NonRepeaters:   1,
				MaxRepetitions: 10,
				VarBinds: []VarBind{
					vb(OID{1, 3, 6, 1, 2, 1, 1, 1, 0}, Null()),
					vb(OID{1, 3, 6, 1, 2, 1, 2, 2, 1, 2}, Null()),
				},
			},
		},
		{
			Version:   VersionV2c,
			Community: []byte("public"),
			PDU: &PDU{
				Type:      PDUInform,
				RequestID: 11,
				VarBinds: []VarBind{
					vb(OID{1, 3, 6, 1, 2, 1, 1, 3, 0}, TimeTicksVal(1)),
					vb(OID{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}, ObjectIdentifier(OID{1, 3, 6, 1, 6, 3, 1, 1, 5, 1})),
				},
			},
		},
		{
			Version:   VersionV2c,
			Community: []byte("public"),
			PDU: &PDU{
				Type:      PDUTrapV2,
				RequestID: 12,
				VarBinds: []VarBind{
					vb(OID{1, 3, 6, 1, 2, 1, 1, 3, 0}, TimeTicksVal(99)),
					vb(OID{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}, ObjectIdentifier(OID{1, 3, 6, 1, 6, 3, 1, 1, 5, 1})),
				},
			},
		},
		{
			Version:   VersionV2c,
			Community: []byte("public"),
			PDU: &PDU{
				Type:      PDUResponse,
				RequestID: 13,
				VarBinds: []VarBind{
					vb(sysDescr(), NoSuchObjectVal()),
					vb(OID{1, 3, 6, 1, 2, 1, 1, 1, 1}, NoSuchInstanceVal()),
					vb(OID{1, 3, 6, 1, 2, 1, 1, 9, 0}, EndOfMibViewVal()),
				},
			},
		},
	}
	for _, in := range cases {
		t.Run(in.Version.String()+"/"+in.PDU.Type.String(), func(t *testing.T) {
			roundTrip(t, in)
		})
	}
}

func TestV3PlaintextRoundTrip(t *testing.T) {
	in := Message{
		Version:          VersionV3,
		MsgID:            99,
		MsgMaxSize:       65507,
		MsgFlags:         FlagReportable,
		MsgSecurityModel: SecurityModelUSM,
		USM: USMParameters{
			EngineID:    []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x01},
			EngineBoots: 1,
			EngineTime:  42,
			UserName:    []byte("alice"),
		},
		ScopedPDU: &ScopedPDU{
			ContextEngineID: []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x01},
			ContextName:     []byte(""),
			PDU: PDU{
				Type:      PDUGet,
				RequestID: 1001,
				VarBinds:  []VarBind{vb(sysDescr(), Null())},
			},
		},
	}
	got := roundTrip(t, in)
	if got.MsgID != 99 || got.PDU.RequestID != 1001 {
		t.Fatalf("ids not preserved msgID=%d request-id=%d", got.MsgID, got.PDU.RequestID)
	}
	if got.Priv() || !got.Reportable() || got.Auth() {
		t.Fatalf("flags %+v", got.MsgFlags)
	}
}

func TestV3EncryptedRoundTrip(t *testing.T) {
	cipher := []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03}
	in := Message{
		Version:          VersionV3,
		MsgID:            7,
		MsgMaxSize:       1400,
		MsgFlags:         FlagAuth | FlagPriv | FlagReportable,
		MsgSecurityModel: SecurityModelUSM,
		USM: USMParameters{
			EngineID:    []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x01},
			EngineBoots: 3,
			EngineTime:  9,
			UserName:    []byte("alice"),
			AuthParams:  bytes.Repeat([]byte{0}, 12),
			PrivParams:  []byte{1, 2, 3, 4, 5, 6, 7, 8},
		},
		EncryptedPDU: cipher,
	}
	got := roundTrip(t, in)
	if !bytes.Equal(got.EncryptedPDU, cipher) {
		t.Fatalf("ciphertext %x", got.EncryptedPDU)
	}
	if got.PDU != nil || got.ScopedPDU != nil {
		t.Fatal("encrypted message must not parse a PDU")
	}
	if !got.Priv() || !got.Auth() {
		t.Fatal("authPriv flags")
	}
}

func TestV3ReportAndGetBulk(t *testing.T) {
	report := Message{
		Version:          VersionV3,
		MsgID:            1,
		MsgMaxSize:       65507,
		MsgFlags:         0,
		MsgSecurityModel: SecurityModelUSM,
		USM: USMParameters{
			EngineID:    []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x02},
			EngineBoots: 1,
			EngineTime:  1,
		},
		ScopedPDU: &ScopedPDU{
			ContextEngineID: []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x02},
			PDU: PDU{
				Type:      PDUReport,
				RequestID: 1,
				VarBinds: []VarBind{
					vb(OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0}, Counter32Val(1)),
				},
			},
		},
	}
	roundTrip(t, report)

	bulk := Message{
		Version:          VersionV3,
		MsgID:            2,
		MsgMaxSize:       484,
		MsgFlags:         FlagReportable,
		MsgSecurityModel: SecurityModelUSM,
		USM:              USMParameters{UserName: []byte("alice")},
		ScopedPDU: &ScopedPDU{
			PDU: PDU{
				Type:           PDUGetBulk,
				RequestID:      55,
				NonRepeaters:   0,
				MaxRepetitions: 5,
				VarBinds:       []VarBind{vb(OID{1, 3, 6, 1, 2, 1}, Null())},
			},
		},
	}
	got := roundTrip(t, bulk)
	if got.PDU.NonRepeaters != 0 || got.PDU.MaxRepetitions != 5 {
		t.Fatalf("bulk fields %+v", got.PDU)
	}
}

func TestV3ScopedPDUHelpers(t *testing.T) {
	sp := ScopedPDU{
		ContextEngineID: []byte{1, 2, 3, 4, 5},
		ContextName:     []byte("ctx"),
		PDU: PDU{
			Type:      PDUGetNext,
			RequestID: 3,
			VarBinds:  []VarBind{vb(sysDescr(), Null())},
		},
	}
	b, err := EncodeScopedPDU(sp)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeScopedPDU(b)
	if err != nil {
		t.Fatal(err)
	}
	if !sp.Equal(&got) {
		t.Fatalf("%+v vs %+v", got, sp)
	}
}

func TestAllVarbindTypes(t *testing.T) {
	in := Message{
		Version:   VersionV2c,
		Community: []byte("public"),
		PDU: &PDU{
			Type:      PDUResponse,
			RequestID: 1,
			VarBinds: []VarBind{
				vb(OID{1, 3, 6, 1, 0}, Int(-1)),
				vb(OID{1, 3, 6, 1, 1}, OctetString([]byte("x"))),
				vb(OID{1, 3, 6, 1, 2}, Null()),
				vb(OID{1, 3, 6, 1, 3}, ObjectIdentifier(OID{1, 3, 6, 1})),
				vb(OID{1, 3, 6, 1, 4}, IPAddr([4]byte{192, 0, 2, 1})),
				vb(OID{1, 3, 6, 1, 5}, Counter32Val(1)),
				vb(OID{1, 3, 6, 1, 6}, Gauge32Val(2)),
				vb(OID{1, 3, 6, 1, 7}, Unsigned32Val(3)),
				vb(OID{1, 3, 6, 1, 8}, TimeTicksVal(4)),
				vb(OID{1, 3, 6, 1, 9}, OpaqueVal([]byte{9})),
				vb(OID{1, 3, 6, 1, 10}, Counter64Val(1<<40)),
			},
		},
	}
	got := roundTrip(t, in)
	if got.PDU.VarBinds[6].Value.Type != TypeGauge32 {
		t.Fatalf("Gauge32 decoded as %s", got.PDU.VarBinds[6].Value.Type)
	}
	// Unsigned32 shares the Gauge32 tag on the wire.
	if got.PDU.VarBinds[7].Value.Type != TypeGauge32 {
		t.Fatalf("Unsigned32 decoded as %s", got.PDU.VarBinds[7].Value.Type)
	}
	if got.PDU.VarBinds[10].Value.Uint != 1<<40 {
		t.Fatalf("counter64=%d", got.PDU.VarBinds[10].Value.Uint)
	}
}

func TestV1GetBulkParseError(t *testing.T) {
	m := Message{
		Version:   VersionV2c,
		Community: []byte("public"),
		PDU: &PDU{
			Type:           PDUGetBulk,
			RequestID:      1,
			NonRepeaters:   0,
			MaxRepetitions: 1,
			VarBinds:       []VarBind{vb(sysDescr(), Null())},
		},
	}
	b := mustEncode(t, m)
	// Rewrite version INTEGER 1 -> 0 (v1) at the first INTEGER after SEQUENCE.
	if b[2] != tagInteger || b[4] != 1 {
		t.Fatalf("unexpected encoding %x", b[:8])
	}
	b[4] = 0
	_, err := Decode(b)
	if err == nil {
		t.Fatal("expected v1 GetBulk parse error")
	}
	if !errors.Is(err, ErrPDU) {
		t.Fatalf("err=%v, want ErrPDU", err)
	}
}

func TestEncodeV1GetBulkRejected(t *testing.T) {
	m := Message{
		Version:   VersionV1,
		Community: []byte("public"),
		PDU:       &PDU{Type: PDUGetBulk, RequestID: 1},
	}
	if _, err := Encode(m); err == nil || !errors.Is(err, ErrPDU) {
		t.Fatalf("err=%v", err)
	}
}

func TestRequestIDPreserved(t *testing.T) {
	const id int32 = 0x7fffffff
	in := Message{
		Version:   VersionV2c,
		Community: []byte("public"),
		PDU: &PDU{
			Type:      PDUGet,
			RequestID: id,
			VarBinds:  []VarBind{vb(sysDescr(), Null())},
		},
	}
	got := roundTrip(t, in)
	if got.PDU.RequestID != id {
		t.Fatalf("request-id %d", got.PDU.RequestID)
	}
}

func TestMaxMessageSizeCap(t *testing.T) {
	in := Message{
		Version:   VersionV2c,
		Community: []byte("public"),
		PDU: &PDU{
			Type:      PDUGet,
			RequestID: 1,
			VarBinds:  []VarBind{vb(sysDescr(), Null())},
		},
	}
	b := mustEncode(t, in)
	if _, err := DecodeMax(b, int64(len(b)-1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("decode cap err=%v", err)
	}
	if _, err := EncodeMax(in, 8); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("encode cap err=%v", err)
	}
	if _, err := Decode(append(b, 0x00)); err == nil {
		t.Fatal("trailing byte must fail")
	}
}

func TestUnsupportedVersion(t *testing.T) {
	if _, err := Encode(Message{Version: 2, PDU: &PDU{Type: PDUGet}}); !errors.Is(err, ErrVersion) {
		t.Fatalf("err=%v", err)
	}
}

func TestV3PrivNotOctetString(t *testing.T) {
	in := Message{
		Version:          VersionV3,
		MsgID:            1,
		MsgMaxSize:       484,
		MsgFlags:         FlagReportable,
		MsgSecurityModel: SecurityModelUSM,
		ScopedPDU: &ScopedPDU{
			PDU: PDU{Type: PDUGet, RequestID: 1, VarBinds: []VarBind{vb(sysDescr(), Null())}},
		},
	}
	b := mustEncode(t, in)
	idx := bytes.Index(b, []byte{tagOctetString, 0x01, FlagReportable})
	if idx < 0 {
		t.Fatalf("msgFlags not found in %x", b)
	}
	b[idx+2] = FlagPriv | FlagReportable
	if _, err := Decode(b); err == nil {
		t.Fatal("priv with SEQUENCE scopedPDU must fail")
	}
}

func roundTrip(t *testing.T, in Message) Message {
	t.Helper()
	b := mustEncode(t, in)
	got, err := Decode(b)
	if err != nil {
		t.Fatalf("decode: %v\n%x", err, b)
	}
	b2, err := Encode(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatalf("encode(decode) bytes differ\n%x\n%x", b, b2)
	}
	if in.Version == VersionV3 && in.ScopedPDU != nil && in.PDU == nil {
		in.PDU = in.ScopedPDU.PDU.clone()
	}
	if in.Version == VersionV3 && in.ScopedPDU != nil {
		if in.ScopedPDU.ContextName == nil {
			in.ScopedPDU.ContextName = []byte{}
		}
	}
	// Unsigned32 encodes as Gauge32.
	if in.PDU != nil {
		for i := range in.PDU.VarBinds {
			if in.PDU.VarBinds[i].Value.Type == TypeUnsigned32 {
				in.PDU.VarBinds[i].Value.Type = TypeGauge32
			}
		}
	}
	if !got.Equal(in) {
		t.Fatalf("semantic mismatch\ngot  %#v\nwant %#v", got, in)
	}
	return got
}
