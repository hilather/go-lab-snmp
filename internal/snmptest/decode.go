package snmptest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/snmpwire"
)

// Decode is a test helper around snmpwire.Decode with the default max size.
func Decode(b []byte) (snmpwire.Message, error) {
	return snmpwire.Decode(b)
}

// MustDecode fails the test if b is not a valid SNMP message.
func MustDecode(t testing.TB, b []byte) snmpwire.Message {
	t.Helper()
	m, err := snmpwire.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// PDU returns the decoded PDU, or nil when only v3 ciphertext is present.
func PDU(m snmpwire.Message) *snmpwire.PDU {
	return m.RequestPDU()
}

// RequestID returns the PDU request-id, or 0 if no PDU was decoded.
func RequestID(m snmpwire.Message) int32 {
	if p := m.RequestPDU(); p != nil {
		return p.RequestID
	}
	return 0
}

// MsgID returns the SNMPv3 msgID (0 for v1/v2c).
func MsgID(m snmpwire.Message) int32 {
	return m.MsgID
}

// LoadPacket reads testdata/packets/<name>.
func LoadPacket(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "packets", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func repoRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
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
