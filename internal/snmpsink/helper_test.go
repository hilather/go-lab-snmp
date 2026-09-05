package snmpsink

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
	"github.com/hilather/go-lab-snmp/internal/store"
	"github.com/hilather/go-lab-snmp/internal/usm"
)

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

func coldStart() snmpwire.OID {
	return snmpwire.OID{1, 3, 6, 1, 6, 3, 1, 1, 5, 1}
}

func startSink(t *testing.T, cfg Config) *Server {
	t.Helper()
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:0"
	}
	if cfg.Store == nil {
		cfg.Store = store.NewTrapRing(store.TrapPolicy{MaxMessages: 32, MaxBytes: 1 << 20, MaxWait: 2 * time.Second})
	}
	if cfg.MaxPerSec == 0 {
		cfg.MaxPerSec = 10000
	}
	if cfg.MaxPerIP == 0 {
		cfg.MaxPerIP = 500
	}
	if len(cfg.Allow) == 0 {
		cfg.Allow = []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
		}
	}
	if cfg.Communities == nil {
		cfg.Communities = map[string]*Community{
			"public": {
				Name:     "public",
				Wire:     []byte("public"),
				Versions: map[string]bool{model.VersionV1: true, model.VersionV2c: true},
			},
		}
	}
	if cfg.Versions == nil {
		cfg.Versions = map[string]bool{
			model.VersionV1: true, model.VersionV2c: true, model.VersionV3: true,
		}
	}
	cfg.RawRetain = true
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	if !s.Ready() {
		t.Fatal("sink not ready")
	}
	return s
}

func dst(s *Server) string {
	return s.Addr().String()
}

func waitOne(t *testing.T, s *Server) *store.TrapRecord {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rec, err := s.Store().Wait(ctx, store.TrapFilter{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func aliceEngine(t *testing.T) *usm.Engine {
	t.Helper()
	id, err := usm.ParseEngineID("80000000046c6162736e6d70aabbccdd")
	if err != nil {
		t.Fatal(err)
	}
	e, err := usm.New(usm.Config{EngineID: id, EngineBoots: 1})
	if err != nil {
		t.Fatal(err)
	}
	auth, priv := aliceSecrets(t)
	if err := e.AddUser(usm.UserConfig{
		Name:           "alice",
		Level:          model.LevelAuthPriv,
		AuthProtocol:   model.AuthSHA256,
		AuthPassphrase: auth,
		PrivProtocol:   model.PrivAES128,
		PrivPassphrase: priv,
		Access:         model.AccessReadWrite,
		Map:            "private-if",
	}); err != nil {
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

func remoteEngine(t *testing.T) *usm.Engine {
	t.Helper()
	e, err := usm.New(usm.Config{EngineID: bytes.Repeat([]byte{0x80}, 8), EngineBoots: 1})
	if err != nil {
		t.Fatal(err)
	}
	auth, priv := aliceSecrets(t)
	if err := e.AddUser(usm.UserConfig{
		Name:           "alice",
		Level:          model.LevelAuthPriv,
		AuthProtocol:   model.AuthSHA256,
		AuthPassphrase: auth,
		PrivProtocol:   model.PrivAES128,
		PrivPassphrase: priv,
	}); err != nil {
		t.Fatal(err)
	}
	return e
}

func wrapTrap(t *testing.T, e *usm.Engine, pdu snmpwire.PDU, reportable bool) []byte {
	t.Helper()
	u := e.User("alice")
	msg := snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            pdu.RequestID,
		MsgMaxSize:       65507,
		MsgFlags:         usm.Flags(model.LevelAuthPriv, reportable),
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		ScopedPDU:        &snmpwire.ScopedPDU{PDU: pdu},
	}
	wire, err := e.Wrap(u, msg)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
