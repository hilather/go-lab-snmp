package compiler

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/model"
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

func TestCompileFullYAML(t *testing.T) {
	t.Chdir(repoRoot(t))
	st, err := config.LoadFile("testdata/config/valid/full.yaml")
	if err != nil {
		t.Fatal(err)
	}
	clk := testutil.NewFakeClock(time.Unix(1_700_000_000, 0))
	snap, err := Compile(st, CompileOpts{Clock: clk, BaseDir: repoRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Revision == "" || snap.Revision[:7] != model.RevisionPrefix {
		t.Fatalf("revision %q", snap.Revision)
	}
	if snap.Maps["public-if"] == nil || snap.Maps["private-if"] == nil {
		t.Fatal("maps")
	}
	pub := snap.LookupCommunity([]byte("public"))
	if pub == nil || pub.Name != "public" || pub.Map != "public-if" {
		t.Fatalf("community %+v", pub)
	}
	if snap.Engine == nil || snap.Engine.User("alice") == nil {
		t.Fatal("usm alice")
	}
	if snap.UptimeEpoch != clk.Now() {
		t.Fatal("uptimeEpoch")
	}
	clk.Advance(time.Second)
	if snap.UptimeTicks() != 100 {
		t.Fatalf("uptime ticks %d", snap.UptimeTicks())
	}
}

func TestCompilePreservesUptimeAndEngineOnApply(t *testing.T) {
	t.Chdir(repoRoot(t))
	st, err := config.LoadFile("testdata/config/valid/full.yaml")
	if err != nil {
		t.Fatal(err)
	}
	clk := testutil.NewFakeClock(time.Unix(1_700_000_000, 0))
	first, err := Compile(st, CompileOpts{Clock: clk, BaseDir: repoRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(5 * time.Second)
	st.Spec.Agent.MaxVarBinds = 32
	second, err := Compile(st, CompileOpts{
		Clock:             clk,
		BaseDir:           repoRoot(t),
		Previous:          first,
		BootstrapRevision: first.BootstrapRevision,
		Generation:        1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.UptimeEpoch != first.UptimeEpoch {
		t.Fatal("uptimeEpoch must survive apply")
	}
	if second.Engine != first.Engine {
		t.Fatal("engine must be reused when users/engine identity are unchanged")
	}
	if second.MaxVarBinds != 32 {
		t.Fatalf("maxVarBinds=%d", second.MaxVarBinds)
	}
}

func TestCompileCopiesTCPDTLSFields(t *testing.T) {
	t.Chdir(repoRoot(t))
	full, err := config.LoadFile("testdata/config/valid/full.yaml")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := Compile(full, CompileOpts{BaseDir: repoRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if snap.TCPEnabled || snap.DTLSEnabled {
		t.Fatalf("default transports: tcp=%v dtls=%v", snap.TCPEnabled, snap.DTLSEnabled)
	}

	tcpSt, err := config.LoadFile("testdata/config/valid/tcp-enabled.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tcpSnap, err := Compile(tcpSt, CompileOpts{BaseDir: repoRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if !tcpSnap.TCPEnabled {
		t.Fatal("tcp.enabled")
	}
	if tcpSnap.TCPAddress != "" {
		t.Fatalf("inherit address must stay empty, got %q", tcpSnap.TCPAddress)
	}
	if tcpSnap.AgentAddress != ":1161" {
		t.Fatalf("agent %q", tcpSnap.AgentAddress)
	}

	only, err := config.LoadFile("testdata/config/valid/tcp-only.yaml")
	if err != nil {
		t.Fatal(err)
	}
	onlySnap, err := Compile(only, CompileOpts{BaseDir: repoRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if !onlySnap.TCPEnabled || onlySnap.AgentEnabled || onlySnap.TCPAddress != ":1161" {
		t.Fatalf("tcp-only %+v enabled=%v addr=%q", onlySnap.AgentEnabled, onlySnap.TCPEnabled, onlySnap.TCPAddress)
	}

	dtlsSt, err := config.LoadFile("testdata/config/valid/dtls-enabled.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dtlsSnap, err := Compile(dtlsSt, CompileOpts{BaseDir: repoRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if !dtlsSnap.DTLSEnabled {
		t.Fatal("dtls.enabled")
	}
	if dtlsSnap.DTLSAddress != config.DefaultDTLSAddress || dtlsSnap.DTLSTrapsAddress != config.DefaultDTLSTrapsAddress {
		t.Fatalf("dtls addrs %q %q", dtlsSnap.DTLSAddress, dtlsSnap.DTLSTrapsAddress)
	}
	if dtlsSnap.DTLSCertFile == "" || dtlsSnap.DTLSKeyFile == "" {
		t.Fatal("dtls cert file refs")
	}
}

func TestCompileRevisionIgnoresOverlay(t *testing.T) {
	t.Chdir(repoRoot(t))
	st, err := config.LoadFile("testdata/config/valid/defaults.yaml")
	if err != nil {
		t.Fatal(err)
	}
	a, err := Compile(st, CompileOpts{BaseDir: repoRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compile(st, CompileOpts{BaseDir: repoRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	if a.Revision != b.Revision {
		t.Fatal("same spec must hash the same")
	}
}
