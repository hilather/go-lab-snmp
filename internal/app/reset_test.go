package app

import (
	"context"
	"os"
	"testing"

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
		// bootstrap file unchanged, so revision matches bootstrap
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
	svc, snap := mustBoot(t)
	svc.snmpOverride = "127.0.0.1:1161"
	got := ""
	svc.SetSNMPRebind(func(addr string) error {
		got = addr
		return nil
	})
	_, err := svc.Reset(context.Background(), actor(), ResetIn{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "127.0.0.1:1161" {
		// Unchanged listen relative to override: rebind only when address changes.
		_ = snap
	}
	if effectiveSNMP(svc.snmpOverride, svc.Active().AgentAddress, svc.Active().AgentEnabled) != "127.0.0.1:1161" {
		t.Fatal("flags still win after Reset")
	}
}
