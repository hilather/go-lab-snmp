package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/snmpagent"
	"github.com/hilather/go-lab-snmp/internal/snmpsink"
	"github.com/hilather/go-lab-snmp/internal/snmptest"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
)

func TestDataPlaneSyncRollbackKeepsOld(t *testing.T) {
	t.Chdir(repoRoot(t))
	svc, err := app.Boot(context.Background(), app.Options{BootstrapPath: "testdata/config/valid/full.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	snap := svc.Active()
	agent, err := snmpagent.New(snmpagent.Config{
		Addr:    "127.0.0.1:0",
		Store:   svc.Snapshots(),
		Overlay: svc.Overlay(),
		Queries: svc.Queries(),
		Clock:   snap.Clock,
		Metrics: observability.NewRegistry(),
	})
	if err != nil {
		t.Fatal(err)
	}
	sink, err := snmpsink.New(snmpsink.Config{
		Store:     svc.Traps(),
		Snapshots: svc.Snapshots(),
		Clock:     sinkClock{snap.Clock},
	})
	if err != nil {
		t.Fatal(err)
	}
	dp := &dataPlane{agent: agent, sink: sink}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = sink.Shutdown(ctx)
		_ = agent.Shutdown(ctx)
	})

	a1 := freeUDPAddr(t)
	t1 := freeUDPAddr(t)
	if err := dp.Sync(app.DesiredListeners{AgentUDP: a1, TrapUDP: t1}); err != nil {
		t.Fatal(err)
	}

	hold, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	a2 := freeUDPAddr(t)
	t2 := hold.LocalAddr().String()
	if err := dp.Sync(app.DesiredListeners{AgentUDP: a2, TrapUDP: t2}); err == nil {
		t.Fatal("expected trap bind failure")
	}

	req := snmptest.MustEncodeGet(t, snmpwire.VersionV2c, "public", 1, snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0})
	m := snmptest.MustExchange(t, a1, req, 2*time.Second)
	p := m.RequestPDU()
	if p == nil || string(p.VarBinds[0].Value.Bytes) != "LabSNMP public-if" {
		t.Fatalf("old agent must keep serving: %+v", p)
	}
	pc, err := net.ListenPacket("udp", a2)
	if err != nil {
		t.Fatalf("new agent bind must roll back: %v", err)
	}
	_ = pc.Close()
	if last := dp.last(); last.AgentUDP != a1 || last.TrapUDP != t1 {
		t.Fatalf("bound snapshot %+v", last)
	}
}

func TestDataPlaneSyncEmptyTrapStops(t *testing.T) {
	t.Chdir(repoRoot(t))
	svc, err := app.Boot(context.Background(), app.Options{BootstrapPath: "testdata/config/valid/full.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	snap := svc.Active()
	agent, err := snmpagent.New(snmpagent.Config{
		Addr:    "127.0.0.1:0",
		Store:   svc.Snapshots(),
		Overlay: svc.Overlay(),
		Queries: svc.Queries(),
		Clock:   snap.Clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	sink, err := snmpsink.New(snmpsink.Config{
		Store:     svc.Traps(),
		Snapshots: svc.Snapshots(),
		Clock:     sinkClock{snap.Clock},
	})
	if err != nil {
		t.Fatal(err)
	}
	dp := &dataPlane{agent: agent, sink: sink}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = sink.Shutdown(ctx)
		_ = agent.Shutdown(ctx)
	})
	a1 := freeUDPAddr(t)
	t1 := freeUDPAddr(t)
	if err := dp.Sync(app.DesiredListeners{AgentUDP: a1, TrapUDP: t1}); err != nil {
		t.Fatal(err)
	}
	if err := dp.Sync(app.DesiredListeners{AgentUDP: a1, TrapUDP: ""}); err != nil {
		t.Fatal(err)
	}
	if sink.Bound() {
		t.Fatal("empty desired trap must stop the socket")
	}
	hold, err := net.ListenPacket("udp", t1)
	if err != nil {
		t.Fatalf("stopped trap address must be free: %v", err)
	}
	_ = hold.Close()
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}
