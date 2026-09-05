package usm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/testutil"
)

func TestDeriveEngineID(t *testing.T) {
	id := DeriveEngineID("testhost")
	if len(id) != 20 {
		t.Fatalf("len %d", len(id))
	}
	wantPrefix := []byte{0x80, 0x00, 0x00, 0x00, 0x04}
	if !bytes.Equal(id[:5], wantPrefix) {
		t.Fatalf("prefix %x", id[:5])
	}
	if string(id[5:12]) != "labsnmp" {
		t.Fatalf("text %q", id[5:12])
	}
	sum := sha256.Sum256([]byte("testhost"))
	if !bytes.Equal(id[12:], sum[:8]) {
		t.Fatalf("hash %x want %x", id[12:], sum[:8])
	}
}

func TestParseEngineID(t *testing.T) {
	got, err := ParseEngineID("80:00:00:00:04:6c:61:62:73:6e:6d:70:aa:bb:cc:dd")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("80000000046c6162736e6d70aabbccdd")
	if !bytes.Equal(got, want) {
		t.Fatalf("%x", got)
	}
	if _, err := ParseEngineID("aabb"); err == nil {
		t.Fatal("too short")
	}
	if _, err := ParseEngineID("zz00"); err == nil {
		t.Fatal("not hex")
	}
}

func TestNewDerivesWhenOmitted(t *testing.T) {
	e, err := New(Config{Hostname: "testhost", EngineBoots: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(e.ID(), DeriveEngineID("testhost")) {
		t.Fatalf("%x", e.ID())
	}
	boots, etime := e.BootsTime()
	if boots != 3 || etime != 0 {
		t.Fatalf("boots=%d time=%d", boots, etime)
	}
}

func TestEngineTimeProcessClock(t *testing.T) {
	clk := testutil.NewFakeClock(time.Unix(1000, 0))
	e, err := New(Config{EngineID: bytes.Repeat([]byte{1}, 8), Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(7 * time.Second)
	_, etime := e.BootsTime()
	if etime != 7 {
		t.Fatalf("engineTime %d", etime)
	}
}

func TestAddUserUnsupportedAlg(t *testing.T) {
	e := mustEngine(t, nil)
	err := e.AddUser(UserConfig{
		Name: "mallory", Level: model.LevelAuthNoPriv,
		AuthProtocol: "sha384", AuthPassphrase: []byte("maplesyrup"),
	})
	if !isUSMAlg(err) {
		t.Fatalf("sha384: %v", err)
	}
	err = e.AddUser(UserConfig{
		Name: "mallory", Level: model.LevelAuthPriv,
		AuthProtocol: model.AuthSHA256, AuthPassphrase: []byte("maplesyrup"),
		PrivProtocol: "aes256", PrivPassphrase: []byte("maplesyrup"),
	})
	if !isUSMAlg(err) {
		t.Fatalf("aes256: %v", err)
	}
}

func TestAddUserAliceFromFiles(t *testing.T) {
	e := mustEngine(t, nil)
	auth, priv := aliceSecrets(t)
	if err := e.AddUser(UserConfig{
		Name: "alice", Level: model.LevelAuthPriv,
		AuthProtocol: model.AuthSHA256, AuthPassphrase: auth,
		PrivProtocol: model.PrivAES128, PrivPassphrase: priv,
		Access: model.AccessReadWrite,
		Map:    "private-if",
	}); err != nil {
		t.Fatal(err)
	}
	u := e.User("alice")
	if u == nil || len(u.authKey) != 32 || len(u.privKey) != 32 {
		t.Fatalf("%+v keys", u)
	}
	ak, pk, err := u.LocalizeFor(e.ID())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ak, u.authKey) || !bytes.Equal(pk, u.privKey) {
		t.Fatal("LocalizeFor must match compiled keys")
	}
}

func mustEngine(t *testing.T, clk Clock) *Engine {
	t.Helper()
	id, _ := hex.DecodeString("80000000046c6162736e6d70aabbccdd")
	e, err := New(Config{EngineID: id, EngineBoots: 1, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func aliceSecrets(t *testing.T) (auth, priv []byte) {
	t.Helper()
	root := repoRoot(t)
	a, err := os.ReadFile(filepath.Join(root, "testdata/secrets/snmp-alice-auth"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.ReadFile(filepath.Join(root, "testdata/secrets/snmp-alice-priv"))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(a), bytes.TrimSpace(p)
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
