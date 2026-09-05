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

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestDataPlaneSyncTCP(t *testing.T) {
	t.Chdir(repoRoot(t))
	svc, err := app.Boot(context.Background(), app.Options{BootstrapPath: "testdata/config/valid/full.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	snap := svc.Active()
	agent, err := snmpagent.New(snmpagent.Config{
		Store:   svc.Snapshots(),
		Overlay: svc.Overlay(),
		Queries: svc.Queries(),
		Clock:   snap.Clock,
		Metrics: observability.NewRegistry(),
		BaseDir: repoRoot(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	dp := &dataPlane{agent: agent}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = agent.Shutdown(ctx)
	})
	tcp := freeTCPAddr(t)
	if err := dp.Sync(app.DesiredListeners{AgentTCP: tcp}); err != nil {
		t.Fatal(err)
	}
	if agent.Bound() {
		t.Fatal("TCP-only Sync must not bind UDP")
	}
	if !agent.BoundTCP() {
		t.Fatal("TCP listener not bound")
	}
	req := snmptest.MustEncodeGet(t, snmpwire.VersionV2c, "public", 1, snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0})
	c, err := net.DialTimeout("tcp", agent.TCPAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := snmpwire.WriteTCP(c, req); err != nil {
		t.Fatal(err)
	}
	raw, err := snmpwire.ReadTCP(c, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	m := snmptest.MustDecode(t, raw)
	p := m.RequestPDU()
	if p == nil || string(p.VarBinds[0].Value.Bytes) != "LabSNMP public-if" {
		t.Fatalf("%+v", p)
	}
}

func TestDataPlaneSyncTCPRollback(t *testing.T) {
	t.Chdir(repoRoot(t))
	svc, err := app.Boot(context.Background(), app.Options{BootstrapPath: "testdata/config/valid/full.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	snap := svc.Active()
	agent, err := snmpagent.New(snmpagent.Config{
		Store:   svc.Snapshots(),
		Overlay: svc.Overlay(),
		Queries: svc.Queries(),
		Clock:   snap.Clock,
		BaseDir: repoRoot(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	dp := &dataPlane{agent: agent}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = agent.Shutdown(ctx)
	})
	tcp1 := freeTCPAddr(t)
	if err := dp.Sync(app.DesiredListeners{AgentTCP: tcp1}); err != nil {
		t.Fatal(err)
	}
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	if err := dp.Sync(app.DesiredListeners{AgentTCP: hold.Addr().String()}); err == nil {
		t.Fatal("expected tcp bind failure")
	}
	if !agent.BoundTCP() {
		t.Fatal("old TCP listener must keep serving")
	}
	req := snmptest.MustEncodeGet(t, snmpwire.VersionV2c, "public", 1, snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0})
	c, err := net.DialTimeout("tcp", agent.TCPAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := snmpwire.WriteTCP(c, req); err != nil {
		t.Fatal(err)
	}
	raw, err := snmpwire.ReadTCP(c, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	m := snmptest.MustDecode(t, raw)
	if p := m.RequestPDU(); p == nil || string(p.VarBinds[0].Value.Bytes) != "LabSNMP public-if" {
		t.Fatalf("old TCP must keep serving: %+v", p)
	}
}

func TestDataPlaneSyncDTLS(t *testing.T) {
	t.Chdir(repoRoot(t))
	svc, err := app.Boot(context.Background(), app.Options{BootstrapPath: "testdata/config/valid/dtls-enabled.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	snap := svc.Active()
	agent, err := snmpagent.New(snmpagent.Config{
		Store:   svc.Snapshots(),
		Overlay: svc.Overlay(),
		Queries: svc.Queries(),
		Clock:   snap.Clock,
		BaseDir: repoRoot(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	dp := &dataPlane{agent: agent}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = agent.Shutdown(ctx)
	})
	dtlsAddr := freeUDPAddr(t)
	if err := dp.Sync(app.DesiredListeners{
		AgentDTLS:    dtlsAddr,
		DTLSCertFile: snap.DTLSCertFile,
		DTLSKeyFile:  snap.DTLSKeyFile,
	}); err != nil {
		t.Fatal(err)
	}
	if !agent.BoundDTLS() {
		t.Fatal("DTLS listener not bound")
	}
}

func TestDataPlaneSyncTrapTCP(t *testing.T) {
	t.Chdir(repoRoot(t))
	svc, err := app.Boot(context.Background(), app.Options{BootstrapPath: "testdata/config/valid/full.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	snap := svc.Active()
	sink, err := snmpsink.New(snmpsink.Config{
		Store:     svc.Traps(),
		Snapshots: svc.Snapshots(),
		Clock:     sinkClock{snap.Clock},
		BaseDir:   repoRoot(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	dp := &dataPlane{sink: sink}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = sink.Shutdown(ctx)
	})
	tcp := freeTCPAddr(t)
	if err := dp.Sync(app.DesiredListeners{TrapTCP: tcp}); err != nil {
		t.Fatal(err)
	}
	if sink.Bound() {
		t.Fatal("TCP-only Sync must not bind UDP")
	}
	if !sink.BoundTCP() {
		t.Fatal("trap TCP listener not bound")
	}
	req := snmptest.MustEncodeInform(t, "public", 15, snmpwire.OID{1, 3, 6, 1, 6, 3, 1, 1, 5, 1})
	c, err := net.DialTimeout("tcp", sink.TCPAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := snmpwire.WriteTCP(c, req); err != nil {
		t.Fatal(err)
	}
	raw, err := snmpwire.ReadTCP(c, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	m := snmptest.MustDecode(t, raw)
	p := m.RequestPDU()
	if p == nil || p.Type != snmpwire.PDUResponse || p.RequestID != 15 {
		t.Fatalf("INFORM ack %+v", p)
	}
}

func TestDataPlaneSyncTrapTCPRollback(t *testing.T) {
	t.Chdir(repoRoot(t))
	svc, err := app.Boot(context.Background(), app.Options{BootstrapPath: "testdata/config/valid/full.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	snap := svc.Active()
	sink, err := snmpsink.New(snmpsink.Config{
		Store:     svc.Traps(),
		Snapshots: svc.Snapshots(),
		Clock:     sinkClock{snap.Clock},
		BaseDir:   repoRoot(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	dp := &dataPlane{sink: sink}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = sink.Shutdown(ctx)
	})
	tcp1 := freeTCPAddr(t)
	if err := dp.Sync(app.DesiredListeners{TrapTCP: tcp1}); err != nil {
		t.Fatal(err)
	}
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	if err := dp.Sync(app.DesiredListeners{TrapTCP: hold.Addr().String()}); err == nil {
		t.Fatal("expected trap tcp bind failure")
	}
	if !sink.BoundTCP() {
		t.Fatal("old trap TCP listener must keep serving")
	}
	req := snmptest.MustEncodeInform(t, "public", 16, snmpwire.OID{1, 3, 6, 1, 6, 3, 1, 1, 5, 1})
	c, err := net.DialTimeout("tcp", sink.TCPAddr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := snmpwire.WriteTCP(c, req); err != nil {
		t.Fatal(err)
	}
	raw, err := snmpwire.ReadTCP(c, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	m := snmptest.MustDecode(t, raw)
	if p := m.RequestPDU(); p == nil || p.Type != snmpwire.PDUResponse {
		t.Fatalf("old trap TCP must keep serving: %+v", p)
	}
}

func TestDataPlaneSyncTrapDTLS(t *testing.T) {
	t.Chdir(repoRoot(t))
	svc, err := app.Boot(context.Background(), app.Options{BootstrapPath: "testdata/config/valid/dtls-enabled.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	snap := svc.Active()
	sink, err := snmpsink.New(snmpsink.Config{
		Store:     svc.Traps(),
		Snapshots: svc.Snapshots(),
		Clock:     sinkClock{snap.Clock},
		BaseDir:   repoRoot(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	dp := &dataPlane{sink: sink}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = sink.Shutdown(ctx)
	})
	dtlsAddr := freeUDPAddr(t)
	if err := dp.Sync(app.DesiredListeners{
		TrapDTLS:     dtlsAddr,
		DTLSCertFile: snap.DTLSCertFile,
		DTLSKeyFile:  snap.DTLSKeyFile,
	}); err != nil {
		t.Fatal(err)
	}
	if !sink.BoundDTLS() {
		t.Fatal("trap DTLS listener not bound")
	}
}
