package snmpsink

import (
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/compiler"
	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
	"github.com/hilather/go-lab-snmp/internal/snmptest"
	"github.com/hilather/go-lab-snmp/internal/store"
)

func TestSinkReloadsSnapshotCommunities(t *testing.T) {
	t.Chdir(repoRoot(t))
	st, err := config.LoadFile("testdata/config/valid/full.yaml")
	if err != nil {
		t.Fatal(err)
	}
	first, err := compiler.Compile(st, compiler.CompileOpts{BaseDir: repoRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	snaps := snapshot.NewStore()
	snaps.InstallBootstrap(first)
	ring := store.NewTrapRing(store.TrapPolicy{MaxMessages: 32, MaxBytes: 1 << 20, MaxWait: 2 * time.Second})
	s := startSink(t, Config{Snapshots: snaps, Store: ring})

	req := snmptest.MustEncodeTrapV2(t, "public", 21, coldStart())
	snmptest.MustSend(t, dst(s), req)
	rec := waitOne(t, s)
	if rec.Community != "public" {
		t.Fatalf("%+v", rec)
	}

	var comms []model.CommunitySpec
	for _, c := range st.Spec.Communities {
		if c.Name != "public" {
			comms = append(comms, c)
		}
	}
	copied := *st
	copied.Spec.Communities = comms
	next, err := compiler.Compile(&copied, compiler.CompileOpts{
		BaseDir:  repoRoot(t),
		Previous: first,
	})
	if err != nil {
		t.Fatal(err)
	}
	snaps.Swap(next)

	before := s.AuthFail.Load()
	snmptest.MustSend(t, dst(s), snmptest.MustEncodeTrapV2(t, "public", 22, coldStart()))
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if s.AuthFail.Load() > before {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("live replaceCommunities must drop unknown community on UDP/162")
}
