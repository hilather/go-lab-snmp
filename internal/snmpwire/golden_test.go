package snmpwire

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGoldenRoundTrip(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "testdata", "packets")
	for _, g := range goldenCases() {
		t.Run(g.name, func(t *testing.T) {
			encoded := mustEncode(t, g.msg)
			path := filepath.Join(dir, g.name+".bin")
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v (run with WRITE_GOLDENS=1 to create)", path, err)
			}
			if !bytes.Equal(encoded, want) {
				t.Fatalf("encode != golden\nencode %x\ngolden %x", encoded, want)
			}
			got, err := Decode(want)
			if err != nil {
				t.Fatal(err)
			}
			again, err := Encode(got)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(again, want) {
				t.Fatalf("encode(decode(golden)) diverged\n%x\n%x", again, want)
			}
			if p := got.RequestPDU(); p != nil && g.msg.RequestPDU() != nil {
				if p.RequestID != g.msg.RequestPDU().RequestID {
					t.Fatalf("request-id %d want %d", p.RequestID, g.msg.RequestPDU().RequestID)
				}
			}
			if got.Version == VersionV3 && got.MsgID != g.msg.MsgID {
				t.Fatalf("msgID %d want %d", got.MsgID, g.msg.MsgID)
			}
		})
	}
}

func TestWriteGoldens(t *testing.T) {
	if os.Getenv("WRITE_GOLDENS") != "1" {
		t.Skip("set WRITE_GOLDENS=1 to rewrite testdata/packets")
	}
	dir := filepath.Join(repoRoot(t), "testdata", "packets")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, g := range goldenCases() {
		b := mustEncode(t, g.msg)
		if err := os.WriteFile(filepath.Join(dir, g.name+".bin"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

type golden struct {
	name string
	msg  Message
}

func goldenCases() []golden {
	sys := OID{1, 3, 6, 1, 2, 1, 1, 1, 0}
	sysUp := OID{1, 3, 6, 1, 2, 1, 1, 3, 0}
	ifDescr := OID{1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1}
	engine := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 'l', 'a', 'b'}
	return []golden{
		{"v1-get", Message{
			Version: VersionV1, Community: []byte("public"),
			PDU: &PDU{Type: PDUGet, RequestID: 1, VarBinds: []VarBind{vb(sys, Null())}},
		}},
		{"v1-getnext", Message{
			Version: VersionV1, Community: []byte("public"),
			PDU: &PDU{Type: PDUGetNext, RequestID: 2, VarBinds: []VarBind{vb(OID{1, 3, 6, 1, 2, 1}, Null())}},
		}},
		{"v1-set", Message{
			Version: VersionV1, Community: []byte("private"),
			PDU: &PDU{Type: PDUSet, RequestID: 3, VarBinds: []VarBind{vb(sys, OctetString([]byte("LabSNMP")))}},
		}},
		{"v1-response", Message{
			Version: VersionV1, Community: []byte("public"),
			PDU: &PDU{Type: PDUResponse, RequestID: 1, VarBinds: []VarBind{vb(sys, OctetString([]byte("LabSNMP")))}},
		}},
		{"v1-trap", Message{
			Version: VersionV1, Community: []byte("public"),
			PDU: &PDU{
				Type: PDUTrapV1, Enterprise: OID{1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1},
				AgentAddr: [4]byte{127, 0, 0, 1}, GenericTrap: TrapColdStart, Timestamp: 100,
				VarBinds: []VarBind{vb(sysUp, TimeTicksVal(100))},
			},
		}},
		{"v2c-get", Message{
			Version: VersionV2c, Community: []byte("public"),
			PDU: &PDU{Type: PDUGet, RequestID: 10, VarBinds: []VarBind{vb(sys, Null())}},
		}},
		{"v2c-getnext", Message{
			Version: VersionV2c, Community: []byte("public"),
			PDU: &PDU{Type: PDUGetNext, RequestID: 11, VarBinds: []VarBind{vb(sys, Null())}},
		}},
		{"v2c-getbulk", Message{
			Version: VersionV2c, Community: []byte("public"),
			PDU: &PDU{Type: PDUGetBulk, RequestID: 12, NonRepeaters: 1, MaxRepetitions: 5,
				VarBinds: []VarBind{vb(sys, Null()), vb(ifDescr, Null())}},
		}},
		{"v2c-set", Message{
			Version: VersionV2c, Community: []byte("private"),
			PDU: &PDU{Type: PDUSet, RequestID: 13, VarBinds: []VarBind{vb(OID{1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 1}, Int(1))}},
		}},
		{"v2c-response", Message{
			Version: VersionV2c, Community: []byte("public"),
			PDU: &PDU{Type: PDUResponse, RequestID: 10, VarBinds: []VarBind{vb(sys, OctetString([]byte("LabSNMP")))}},
		}},
		{"v2c-trap", Message{
			Version: VersionV2c, Community: []byte("public"),
			PDU: &PDU{Type: PDUTrapV2, RequestID: 14, VarBinds: []VarBind{
				vb(sysUp, TimeTicksVal(5)),
				vb(OID{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}, ObjectIdentifier(OID{1, 3, 6, 1, 6, 3, 1, 1, 5, 1})),
			}},
		}},
		{"v2c-inform", Message{
			Version: VersionV2c, Community: []byte("public"),
			PDU: &PDU{Type: PDUInform, RequestID: 15, VarBinds: []VarBind{
				vb(sysUp, TimeTicksVal(6)),
				vb(OID{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}, ObjectIdentifier(OID{1, 3, 6, 1, 6, 3, 1, 1, 5, 1})),
			}},
		}},
		{"v3-get", Message{
			Version: VersionV3, MsgID: 20, MsgMaxSize: 65507, MsgFlags: FlagReportable,
			MsgSecurityModel: SecurityModelUSM,
			USM:              USMParameters{EngineID: engine, EngineBoots: 1, EngineTime: 10, UserName: []byte("alice")},
			ScopedPDU: &ScopedPDU{ContextEngineID: engine, PDU: PDU{
				Type: PDUGet, RequestID: 20, VarBinds: []VarBind{vb(sys, Null())},
			}},
		}},
		{"v3-getbulk", Message{
			Version: VersionV3, MsgID: 21, MsgMaxSize: 65507, MsgFlags: FlagReportable,
			MsgSecurityModel: SecurityModelUSM,
			USM:              USMParameters{EngineID: engine, EngineBoots: 1, EngineTime: 11, UserName: []byte("alice")},
			ScopedPDU: &ScopedPDU{ContextEngineID: engine, PDU: PDU{
				Type: PDUGetBulk, RequestID: 21, NonRepeaters: 0, MaxRepetitions: 8,
				VarBinds: []VarBind{vb(OID{1, 3, 6, 1, 2, 1}, Null())},
			}},
		}},
		{"v3-report", Message{
			Version: VersionV3, MsgID: 22, MsgMaxSize: 65507, MsgFlags: 0,
			MsgSecurityModel: SecurityModelUSM,
			USM:              USMParameters{EngineID: engine, EngineBoots: 1, EngineTime: 12},
			ScopedPDU: &ScopedPDU{ContextEngineID: engine, PDU: PDU{
				Type: PDUReport, RequestID: 22,
				VarBinds: []VarBind{vb(OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0}, Counter32Val(1))},
			}},
		}},
		{"v3-encrypted", Message{
			Version: VersionV3, MsgID: 23, MsgMaxSize: 1400,
			MsgFlags: FlagAuth | FlagPriv | FlagReportable, MsgSecurityModel: SecurityModelUSM,
			USM: USMParameters{
				EngineID: engine, EngineBoots: 1, EngineTime: 13, UserName: []byte("alice"),
				AuthParams: bytes.Repeat([]byte{0xaa}, 12), PrivParams: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			},
			EncryptedPDU: []byte("ciphertext-not-usm"),
		}},
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
