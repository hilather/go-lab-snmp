package app

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/store"
)

func TestResetRestoresBootstrapAfterSET(t *testing.T) {
	svc, _ := mustBoot(t)
	a := actor()
	oid := "1.3.6.1.2.1.2.2.1.8.1"
	if _, err := svc.SetOID(context.Background(), a, OIDSetIn{
		Map:   "public-if",
		OID:   oid,
		Value: mibtree.Value{Type: model.TypeInteger, Signed: 5},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetOID(context.Background(), a, OIDGetIn{Map: "public-if", OID: oid})
	if err != nil {
		t.Fatal(err)
	}
	if got.Value.Signed != 5 {
		t.Fatalf("overlay %+v", got)
	}

	beforeRev := svc.Active().Revision
	res, err := svc.Reset(context.Background(), a, ResetIn{Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied {
		t.Fatal("reset")
	}
	got, err = svc.GetOID(context.Background(), a, OIDGetIn{Map: "public-if", OID: oid})
	if err != nil {
		t.Fatal(err)
	}
	if got.Overlay || got.Value.Signed != 1 {
		t.Fatalf("reset must restore bootstrap: %+v", got)
	}
	if svc.Active().Revision != beforeRev {
		t.Fatalf("reset revision %s want %s", svc.Active().Revision, beforeRev)
	}
	if _, ok := svc.Overlay().Get("public-if", oid); ok {
		t.Fatal("overlay still set")
	}
}

func TestResetWipesTrapsAndQueries(t *testing.T) {
	svc, _ := mustBoot(t)
	if _, err := svc.Traps().Insert(store.TrapRecord{Version: "v2c", PDUType: "trap", Community: "public"}); err != nil {
		t.Fatal(err)
	}
	svc.Queries().Insert(store.Query{Type: "get", Identity: "public", Decision: "ok"})
	if svc.Traps().Stats().Messages == 0 || svc.Queries().Len() == 0 {
		t.Fatal("seed")
	}
	res, err := svc.Reset(context.Background(), actor(), ResetIn{Reason: "wipe"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied {
		t.Fatal("reset")
	}
	if svc.Traps().Stats().Messages != 0 {
		t.Fatal("traps wiped")
	}
	if svc.Queries().Len() != 0 {
		t.Fatal("queries wiped")
	}
}

func TestResetNeverWritesBootstrap(t *testing.T) {
	path := copyFull(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := Boot(context.Background(), Options{BootstrapPath: path})
	if err != nil {
		t.Fatal(err)
	}
	a := actor()
	_, err = svc.Apply(context.Background(), a, ChangeIn{
		ExpectedRevision: svc.Active().Revision,
		IdempotencyKey:   "reset-never-writes",
		Operations: []model.Operation{{
			Op:        model.OpReplaceAdmission,
			Admission: &model.AdmissionSpec{AllowClientCidrs: []string{"10.0.0.0/8"}, MaxDatagramsPerSec: 1, MaxDatagramsPerIP: 1},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Reset(context.Background(), a, ResetIn{}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("reset must never write bootstrap")
	}
	cidrs := svc.Active().Canonical.Spec.Admission.AllowClientCidrs
	if len(cidrs) < 1 || cidrs[0] == "10.0.0.0/8" {
		t.Fatalf("reset must reread bootstrap admission, got %v", cidrs)
	}
}

func TestResetFlagsStillWin(t *testing.T) {
	svc, _ := mustBoot(t)
	svc.snmpOverride = "127.0.0.1:1161"
	var got DesiredListeners
	svc.SetDataPlaneSync(func(desired DesiredListeners) error {
		got = desired
		return nil
	})
	_, err := svc.Reset(context.Background(), actor(), ResetIn{})
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentUDP != "127.0.0.1:1161" {
		t.Fatalf("flags still win: %+v", got)
	}
	if effectiveSNMP(svc.snmpOverride, svc.Active().AgentAddress, svc.Active().AgentEnabled) != "127.0.0.1:1161" {
		t.Fatal("flags still win after Reset")
	}
}

func TestResetDataPlaneSyncFromNextBeforeSwap(t *testing.T) {
	path := copyFull(t)
	svc, err := Boot(context.Background(), Options{BootstrapPath: path})
	if err != nil {
		t.Fatal(err)
	}
	old := svc.Active().AgentAddress
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(body), `address: ":161"`, `address: "127.0.0.1:1161"`, 1)
	if rewritten == string(body) {
		t.Fatal("fixture agent.address")
	}
	if err := os.WriteFile(path, []byte(rewritten), 0o644); err != nil {
		t.Fatal(err)
	}

	var got DesiredListeners
	var activeDuring string
	svc.SetDataPlaneSync(func(desired DesiredListeners) error {
		got = desired
		activeDuring = svc.Active().AgentAddress
		return nil
	})
	if _, err := svc.Reset(context.Background(), actor(), ResetIn{Reason: "rebind"}); err != nil {
		t.Fatal(err)
	}
	if got.AgentUDP != "127.0.0.1:1161" {
		t.Fatalf("desired from next: %+v", got)
	}
	if activeDuring != old {
		t.Fatalf("hook must run before Swap: active=%s old=%s", activeDuring, old)
	}
	if svc.Active().AgentAddress != "127.0.0.1:1161" {
		t.Fatalf("after Swap %s", svc.Active().AgentAddress)
	}
}

func TestResetEmptyDesiredUDPStops(t *testing.T) {
	path := copyFull(t)
	svc, err := Boot(context.Background(), Options{BootstrapPath: path})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(body),
		"    traps:\n      enabled: true\n      address: \":162\"",
		"    traps:\n      enabled: false\n      address: \":162\"",
		1)
	if rewritten == string(body) {
		t.Fatal("fixture traps.enabled")
	}
	if err := os.WriteFile(path, []byte(rewritten), 0o644); err != nil {
		t.Fatal(err)
	}

	var got DesiredListeners
	called := false
	svc.SetDataPlaneSync(func(desired DesiredListeners) error {
		called = true
		got = desired
		return nil
	})
	if _, err := svc.Reset(context.Background(), actor(), ResetIn{}); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("empty trap UDP must still call Sync")
	}
	if got.TrapUDP != "" {
		t.Fatalf("empty desired trap: %+v", got)
	}
}

func TestResetInheritedTCPFollowsUDP(t *testing.T) {
	path := copyNamed(t, "tcp-enabled.yaml")
	svc, err := Boot(context.Background(), Options{BootstrapPath: path})
	if err != nil {
		t.Fatal(err)
	}
	oldUDP := svc.Active().AgentAddress
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(body), `address: ":1161"`, `address: "127.0.0.1:2161"`, 1)
	if rewritten == string(body) {
		t.Fatal("fixture agent.address")
	}
	if err := os.WriteFile(path, []byte(rewritten), 0o644); err != nil {
		t.Fatal(err)
	}

	var got DesiredListeners
	var activeDuring string
	svc.SetDataPlaneSync(func(desired DesiredListeners) error {
		got = desired
		activeDuring = svc.Active().AgentAddress
		return nil
	})
	if _, err := svc.Reset(context.Background(), actor(), ResetIn{Reason: "inherit-tcp"}); err != nil {
		t.Fatal(err)
	}
	if got.AgentUDP != "127.0.0.1:2161" || got.AgentTCP != "127.0.0.1:2161" {
		t.Fatalf("inherited TCP must follow next UDP: %+v", got)
	}
	if got.TrapUDP != ":1162" || got.TrapTCP != ":1162" {
		t.Fatalf("trap inherit: %+v", got)
	}
	if activeDuring != oldUDP {
		t.Fatalf("hook must run before Swap: active=%s old=%s", activeDuring, oldUDP)
	}
}

func TestResetDTLSDesiredFromNext(t *testing.T) {
	svc, _ := mustBootNamed(t, "dtls-enabled.yaml")
	var got DesiredListeners
	svc.SetDataPlaneSync(func(desired DesiredListeners) error {
		got = desired
		return nil
	})
	if _, err := svc.Reset(context.Background(), actor(), ResetIn{}); err != nil {
		t.Fatal(err)
	}
	if got.AgentDTLS != ":10161" || got.TrapDTLS != ":10162" {
		t.Fatalf("dtls desired from next: %+v", got)
	}
	if got.AgentTCP != "" {
		t.Fatalf("tcp off: %+v", got)
	}
}

func TestResetDTLSOverrideOff(t *testing.T) {
	path := copyNamed(t, "dtls-enabled.yaml")
	svc, err := Boot(context.Background(), Options{BootstrapPath: path, DTLSListenOverride: "off"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	var got DesiredListeners
	svc.SetDataPlaneSync(func(desired DesiredListeners) error {
		got = desired
		return nil
	})
	if _, err := svc.Reset(context.Background(), actor(), ResetIn{}); err != nil {
		t.Fatal(err)
	}
	if got.AgentDTLS != "" {
		t.Fatalf("dtls-listen=off: %+v", got)
	}
	if got.TrapDTLS != ":10162" {
		t.Fatalf("trap dtls still on: %+v", got)
	}
}

func TestResetTCPOnlyDesired(t *testing.T) {
	svc, _ := mustBootNamed(t, "tcp-only.yaml")
	var got DesiredListeners
	svc.SetDataPlaneSync(func(desired DesiredListeners) error {
		got = desired
		return nil
	})
	if _, err := svc.Reset(context.Background(), actor(), ResetIn{}); err != nil {
		t.Fatal(err)
	}
	if got.AgentUDP != "" {
		t.Fatalf("tcp-only UDP must be off: %+v", got)
	}
	if got.AgentTCP != ":1161" {
		t.Fatalf("tcp-only AgentTCP: %+v", got)
	}
	if got.TrapTCP != "" {
		t.Fatalf("tcp-only TrapTCP off: %+v", got)
	}
}

func TestResetDataPlaneSyncErrorKeepsSnapshot(t *testing.T) {
	svc, snap := mustBoot(t)
	rev := snap.Revision
	svc.SetDataPlaneSync(func(desired DesiredListeners) error {
		return errors.New("bind failed")
	})
	_, err := svc.Reset(context.Background(), actor(), ResetIn{})
	if err == nil {
		t.Fatal("expected bind error")
	}
	if svc.Active().Revision != rev {
		t.Fatal("failed Sync must leave the snapshot unchanged")
	}
}

func TestApplyAndResetMaxWait(t *testing.T) {
	svc, snap := mustBoot(t)
	a := actor()
	tp := snap.Canonical.Spec.Traps
	tp.MaxWait = 80 * time.Millisecond
	res, err := svc.Apply(context.Background(), a, ChangeIn{
		ExpectedRevision: snap.Revision,
		IdempotencyKey:   "maxwait-apply",
		Operations:       []model.Operation{{Op: model.OpReplaceTrapStorePolicy, TrapStorePolicy: &tp}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Traps().Policy().MaxWait != 80*time.Millisecond {
		t.Fatalf("apply maxWait %s", svc.Traps().Policy().MaxWait)
	}
	start := time.Now()
	_, err = svc.WaitTraps(context.Background(), a, TrapWaitIn{Filter: store.TrapFilter{PDUType: "missing"}, Timeout: 5 * time.Second})
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeWaitTimeout {
		t.Fatalf("wait after apply: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("apply maxWait not live: %s", time.Since(start))
	}

	path := copyFull(t)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(body), "maxWait: 60s", "maxWait: 90ms", 1)
	if rewritten == string(body) {
		t.Fatal("fixture maxWait")
	}
	if err := os.WriteFile(path, []byte(rewritten), 0o644); err != nil {
		t.Fatal(err)
	}
	svc2, err := Boot(context.Background(), Options{BootstrapPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc2.Apply(context.Background(), a, ChangeIn{
		ExpectedRevision: svc2.Active().Revision,
		IdempotencyKey:   "maxwait-before-reset",
		Operations: []model.Operation{{
			Op:              model.OpReplaceTrapStorePolicy,
			TrapStorePolicy: &model.TrapStoreSpec{MaxMessages: 1000, MaxBytes: 16 << 20, FullPolicy: model.FullPolicyEvictOldest, MaxWait: time.Second, RawRetain: true},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if svc2.Traps().Policy().MaxWait != time.Second {
		t.Fatalf("pre-reset maxWait %s", svc2.Traps().Policy().MaxWait)
	}
	if _, err := svc2.Reset(context.Background(), a, ResetIn{Reason: "maxwait"}); err != nil {
		t.Fatal(err)
	}
	if svc2.Traps().Policy().MaxWait != 90*time.Millisecond {
		t.Fatalf("reset maxWait %s", svc2.Traps().Policy().MaxWait)
	}
	start = time.Now()
	_, err = svc2.WaitTraps(context.Background(), a, TrapWaitIn{Filter: store.TrapFilter{PDUType: "missing"}, Timeout: 5 * time.Second})
	de, ok = domainerr.As(err)
	if !ok || de.Code != domainerr.CodeWaitTimeout {
		t.Fatalf("wait after reset: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("reset maxWait not live: %s", time.Since(start))
	}
	_ = res
}
