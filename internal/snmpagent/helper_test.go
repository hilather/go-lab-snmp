package snmpagent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/compiler"
	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
	"github.com/hilather/go-lab-snmp/internal/snmptest"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
	"github.com/hilather/go-lab-snmp/internal/store"
	"github.com/hilather/go-lab-snmp/internal/testutil"
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

func loadFull(t *testing.T, clk Clock) *snapshot.Snapshot {
	t.Helper()
	t.Chdir(repoRoot(t))
	st, err := config.LoadFile("testdata/config/valid/full.yaml")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := compiler.Compile(st, compiler.CompileOpts{Clock: clockAsTestutil(clk), BaseDir: repoRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func loadYAML(t *testing.T, yaml string, clk Clock) *snapshot.Snapshot {
	t.Helper()
	t.Chdir(repoRoot(t))
	st, err := config.Load([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := compiler.Compile(st, compiler.CompileOpts{Clock: clockAsTestutil(clk), BaseDir: repoRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func startAgent(t *testing.T, snap *snapshot.Snapshot) *Server {
	t.Helper()
	st := snapshot.NewStore()
	st.InstallBootstrap(snap)
	s, err := New(Config{
		Addr:    "127.0.0.1:0",
		Store:   st,
		Overlay: store.NewOverlay(),
		Queries: store.NewQueryRing(store.DefaultQueryRing),
		Clock:   snap.Clock,
		Metrics: observability.NewRegistry(),
	})
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
	return s
}

func readTrimmed(path, baseDir string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil && baseDir != "" {
		b, err = os.ReadFile(filepath.Join(baseDir, path))
	}
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(b), nil
}

func dst(s *Server) string {
	return s.Addr().String()
}

func oid(arcs ...uint32) snmpwire.OID {
	out := make(snmpwire.OID, len(arcs))
	copy(out, arcs)
	return out
}

func sysDescr() snmpwire.OID  { return oid(1, 3, 6, 1, 2, 1, 1, 1, 0) }
func sysUpTime() snmpwire.OID { return oid(1, 3, 6, 1, 2, 1, 1, 3, 0) }
func ifOper() snmpwire.OID    { return oid(1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1) }
func labPrivate() snmpwire.OID {
	return oid(1, 3, 6, 1, 4, 1, 99999, 1, 0)
}

func getResp(t *testing.T, s *Server, ver snmpwire.Version, community string, o snmpwire.OID) snmpwire.Message {
	t.Helper()
	req := snmptest.MustEncodeGet(t, ver, community, 1, o)
	return snmptest.MustExchange(t, dst(s), req, 2*time.Second)
}

func fakeClock() *testutil.FakeClock {
	return testutil.NewFakeClock(time.Unix(1_700_000_000, 0))
}

func clockAsTestutil(clk Clock) testutil.Clock {
	if clk == nil {
		return nil
	}
	if tclk, ok := clk.(testutil.Clock); ok {
		return tclk
	}
	return clockShim{clk}
}

type clockShim struct{ Clock }

func (c clockShim) Now() time.Time { return c.Clock.Now() }

const rwYAML = `
apiVersion: labsnmp.dev/v1alpha1
kind: LabSNMP
metadata:
  name: rw
spec:
  maps:
    - name: rw
      objects:
        - oid: "1.3.6.1.2.1.1.1.0"
          type: octetString
          access: read
          value: "descr"
        - oid: "1.3.6.1.2.1.1.3.0"
          type: timeTicks
          access: read
          valueFrom: uptime
        - oid: "1.3.6.1.2.1.2.2.1.8.1"
          type: integer
          access: write
          value: 1
          range: { min: 1, max: 7 }
        - oid: "1.3.6"
          type: integer
          access: read
          value: 1
        - oid: "1.3.6.1"
          type: integer
          access: read
          value: 2
        - oid: "1.3.10"
          type: integer
          access: read
          value: 3
  communities:
    - name: public
      communityFile: testdata/secrets/snmp-public
      versions: [v1, v2c]
      access: read
      map: rw
    - name: private
      communityFile: testdata/secrets/snmp-private
      versions: [v1, v2c]
      access: read-write
      map: rw
  users:
    - name: alice
      level: authPriv
      auth:
        protocol: sha256
        secretFile: testdata/secrets/snmp-alice-auth
      priv:
        protocol: aes128
        secretFile: testdata/secrets/snmp-alice-priv
      access: read-write
      map: rw
`
