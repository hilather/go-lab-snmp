package snmptest

import (
	"testing"

	"github.com/hilather/go-lab-snmp/internal/snmpwire"
)

func TestLoadAndDecodeGoldens(t *testing.T) {
	cases := []struct {
		file    string
		version snmpwire.Version
		pdu     snmpwire.PDUType
		id      int32
		priv    bool
	}{
		{"v1-get.bin", snmpwire.VersionV1, snmpwire.PDUGet, 1, false},
		{"v1-getnext.bin", snmpwire.VersionV1, snmpwire.PDUGetNext, 2, false},
		{"v1-set.bin", snmpwire.VersionV1, snmpwire.PDUSet, 3, false},
		{"v1-response.bin", snmpwire.VersionV1, snmpwire.PDUResponse, 1, false},
		{"v1-trap.bin", snmpwire.VersionV1, snmpwire.PDUTrapV1, 0, false},
		{"v2c-get.bin", snmpwire.VersionV2c, snmpwire.PDUGet, 10, false},
		{"v2c-getnext.bin", snmpwire.VersionV2c, snmpwire.PDUGetNext, 11, false},
		{"v2c-getbulk.bin", snmpwire.VersionV2c, snmpwire.PDUGetBulk, 12, false},
		{"v2c-set.bin", snmpwire.VersionV2c, snmpwire.PDUSet, 13, false},
		{"v2c-response.bin", snmpwire.VersionV2c, snmpwire.PDUResponse, 10, false},
		{"v2c-trap.bin", snmpwire.VersionV2c, snmpwire.PDUTrapV2, 14, false},
		{"v2c-inform.bin", snmpwire.VersionV2c, snmpwire.PDUInform, 15, false},
		{"v3-get.bin", snmpwire.VersionV3, snmpwire.PDUGet, 20, false},
		{"v3-getbulk.bin", snmpwire.VersionV3, snmpwire.PDUGetBulk, 21, false},
		{"v3-report.bin", snmpwire.VersionV3, snmpwire.PDUReport, 22, false},
		{"v3-encrypted.bin", snmpwire.VersionV3, 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			raw := LoadPacket(t, tc.file)
			m := MustDecode(t, raw)
			if m.Version != tc.version {
				t.Fatalf("version %s", m.Version)
			}
			if tc.priv {
				if !m.Priv() || len(m.EncryptedPDU) == 0 || PDU(m) != nil {
					t.Fatalf("expected ciphertext-only message: priv=%v pdu=%v", m.Priv(), PDU(m))
				}
				if MsgID(m) != 23 {
					t.Fatalf("msgID %d", MsgID(m))
				}
				return
			}
			p := PDU(m)
			if p == nil {
				t.Fatal("missing PDU")
			}
			if p.Type != tc.pdu {
				t.Fatalf("pdu %s want %s", p.Type, tc.pdu)
			}
			if p.Type != snmpwire.PDUTrapV1 && RequestID(m) != tc.id {
				t.Fatalf("request-id %d want %d", RequestID(m), tc.id)
			}
			if tc.version == snmpwire.VersionV3 && MsgID(m) != tc.id {
				t.Fatalf("msgID %d want %d", MsgID(m), tc.id)
			}
		})
	}
}

func TestDecodeError(t *testing.T) {
	if _, err := Decode([]byte{0x30, 0x00}); err == nil {
		t.Fatal("expected error")
	}
}
