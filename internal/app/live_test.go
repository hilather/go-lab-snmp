package app

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func TestLiveVsResetOnly(t *testing.T) {
	svc, snap := mustBoot(t)
	ctx := context.Background()
	a := actor()

	feats, err := svc.Features(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	live := map[string]bool{}
	resetOnly := map[string]bool{}
	for _, f := range feats.Items {
		if f.Apply == FeatureApplyLive {
			live[f.ID] = true
		}
		if f.Apply == FeatureApplyResetOnly {
			resetOnly[f.ID] = true
		}
	}
	for _, id := range []string{"maps", "communities", "users", "trapStorePolicy", "admission", "agentCaps", "observability"} {
		if !live[id] {
			t.Errorf("expected live %s", id)
		}
	}
	for _, id := range []string{"listeners.agent.address", "auth", "engine"} {
		if !resetOnly[id] {
			t.Errorf("expected reset-only %s", id)
		}
	}
	if live["ui.enabled"] || resetOnly["ui.enabled"] {
		t.Fatal("do not list ui.enabled")
	}
	if live["dtls"] || resetOnly["dtls"] || live["tcp"] || resetOnly["tcp"] {
		t.Fatal("do not mint dtls/tcp feature ids")
	}

	res, err := svc.Apply(ctx, a, ChangeIn{
		ExpectedRevision: snap.Revision,
		Operations: []model.Operation{{
			Op:        model.OpReplaceAdmission,
			Admission: &model.AdmissionSpec{AllowClientCidrs: []string{"127.0.0.0/8", "::1/128"}, MaxDatagramsPerSec: 1000, MaxDatagramsPerIP: 100},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Applied {
		t.Fatal("apply")
	}

	_, err = svc.Apply(ctx, a, ChangeIn{
		ExpectedRevision: res.RuntimeRevision,
		Operations:       []model.Operation{{Op: "replaceListeners"}},
	})
	requireCode(t, err, domainerr.CodeValidationFailed)
	de, _ := domainerr.As(err)
	if de.Remediation == "" {
		t.Fatal("remediation")
	}
}

func TestApplyRequiresExpectedRevision(t *testing.T) {
	svc, _ := mustBoot(t)
	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		Operations: []model.Operation{{
			Op:        model.OpReplaceAdmission,
			Admission: &model.AdmissionSpec{AllowClientCidrs: []string{"127.0.0.0/8"}, MaxDatagramsPerSec: 1, MaxDatagramsPerIP: 1},
		}},
	})
	requireCode(t, err, domainerr.CodeValidationFailed)
}

func TestApplyRevisionMismatch(t *testing.T) {
	svc, _ := mustBoot(t)
	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: "sha256:deadbeef",
		Operations: []model.Operation{{
			Op:        model.OpReplaceAdmission,
			Admission: &model.AdmissionSpec{AllowClientCidrs: []string{"127.0.0.0/8"}, MaxDatagramsPerSec: 1, MaxDatagramsPerIP: 1},
		}},
	})
	requireCode(t, err, domainerr.CodeRevisionMismatch)
	de, _ := domainerr.As(err)
	if de.CurrentRevision == "" {
		t.Fatal("currentRevision")
	}
}

func TestIdempotentApply(t *testing.T) {
	svc, snap := mustBoot(t)
	in := ChangeIn{
		ExpectedRevision: snap.Revision,
		IdempotencyKey:   "k1",
		Operations: []model.Operation{{
			Op:        model.OpReplaceAdmission,
			Admission: &model.AdmissionSpec{AllowClientCidrs: []string{"127.0.0.0/8", "::1/128"}, MaxDatagramsPerSec: 42, MaxDatagramsPerIP: 7},
		}},
	}
	a := actor()
	r1, err := svc.Apply(context.Background(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := svc.Apply(context.Background(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	if r1.RuntimeRevision != r2.RuntimeRevision {
		t.Fatal("idempotent replay must return the same revision")
	}
	in.Reason = "other"
	_, err = svc.Apply(context.Background(), a, in)
	requireCode(t, err, domainerr.CodeIdempotencyConflict)
}

func TestSetOIDSharesOverlay(t *testing.T) {
	svc, _ := mustBoot(t)
	a := actor()
	oid := "1.3.6.1.2.1.2.2.1.8.1"
	got, err := svc.GetOID(context.Background(), a, OIDGetIn{Map: "public-if", OID: oid})
	if err != nil {
		t.Fatal(err)
	}
	if got.Value.Signed != 1 || got.Overlay {
		t.Fatalf("bootstrap %+v", got)
	}
	before := svc.Overlay().Generation()
	set, err := svc.SetOID(context.Background(), a, OIDSetIn{
		Map:   "public-if",
		OID:   oid,
		Value: mibtree.Value{Type: model.TypeInteger, Signed: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !set.Overlay || set.Value.Signed != 2 {
		t.Fatalf("set %+v", set)
	}
	if svc.Overlay().Generation() <= before {
		t.Fatal("storeGeneration")
	}
	if svc.Active().Revision == "" {
		t.Fatal("revision")
	}
	st, err := svc.GetState(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if st.RuntimeRevision != svc.Active().Revision {
		t.Fatal("oids:set must not change revision")
	}
}
