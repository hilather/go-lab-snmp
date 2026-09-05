package app

import (
	"context"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/observability"
)

func TestHealthFactsFailClosed(t *testing.T) {
	svc, _ := mustBoot(t)
	f := svc.HealthFacts()
	if f.AgentBound || f.TrapBound || f.MgmtBound || f.MgmtOff || f.AgentOff || f.TrapOff {
		t.Fatalf("default facts must not assume UDP/mgmt listeners: %+v", f)
	}
	if !f.TCPOff || !f.TrapTCPOff || !f.DTLSOff || !f.TrapDTLSOff {
		t.Fatalf("disabled transports must overlay Off: %+v", f)
	}
	if observability.Evaluate(f).Ready {
		t.Fatal("ready without SetHealth")
	}
	svc.SetHealth(func() observability.Facts {
		return observability.Facts{AgentBound: true, TrapOff: true, MgmtOff: true}
	})
	if !observability.Evaluate(svc.HealthFacts()).Ready {
		t.Fatal("SetHealth should make ready")
	}
}

func TestHealthFactsDefaultYAMLStaysReady(t *testing.T) {
	svc, _ := mustBoot(t)
	svc.SetHealth(func() observability.Facts {
		return observability.Facts{AgentBound: true, TrapBound: true, MgmtOff: true}
	})
	f := svc.HealthFacts()
	if !f.TCPOff || !f.DTLSOff {
		t.Fatalf("tcp.enabled false must overlay TCPOff: %+v", f)
	}
	if !observability.Evaluate(f).Ready {
		t.Fatal("default YAML tcp.enabled false must stay Ready")
	}
}

func TestHealthFactsTCPOnlyOverlaysAgentOff(t *testing.T) {
	svc, _ := mustBootNamed(t, "tcp-only.yaml")
	f := svc.HealthFacts()
	if !f.AgentOff || !f.TrapOff {
		t.Fatalf("udp off: %+v", f)
	}
	if f.TCPOff {
		t.Fatalf("agent TCP on: %+v", f)
	}
	if !f.TrapTCPOff {
		t.Fatalf("trap TCP off: %+v", f)
	}
}

func TestHealthFactsTCPEnabledUnboundNotReady(t *testing.T) {
	svc, _ := mustBootNamed(t, "tcp-enabled.yaml")
	svc.SetHealth(func() observability.Facts {
		return observability.Facts{AgentBound: true, TrapBound: true, MgmtOff: true}
	})
	f := svc.HealthFacts()
	if f.TCPOff || f.TrapTCPOff {
		t.Fatalf("enabled TCP must not overlay Off: %+v", f)
	}
	if observability.Evaluate(f).Ready {
		t.Fatal("tcp.enabled unbound must not be Ready")
	}
}

func TestStatusListenersUDPOnly(t *testing.T) {
	svc, _ := mustBoot(t)
	st, err := svc.Status(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, l := range st.Listeners {
		got[l.Name] = l.Address
	}
	for _, n := range []string{"agent", "traps", "management"} {
		if _, ok := got[n]; !ok {
			t.Fatalf("missing %s: %+v", n, st.Listeners)
		}
	}
	for _, n := range []string{"agent-tcp", "traps-tcp", "agent-dtls", "traps-dtls"} {
		if _, ok := got[n]; ok {
			t.Fatalf("disabled transport listed: %s", n)
		}
	}
}

func TestStatusListenersTCPEnabled(t *testing.T) {
	svc, _ := mustBootNamed(t, "tcp-enabled.yaml")
	st, err := svc.Status(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, l := range st.Listeners {
		got[l.Name] = l.Address
	}
	if got["agent-tcp"] != ":1161" || got["traps-tcp"] != ":1162" {
		t.Fatalf("inherited TCP status: %+v", st.Listeners)
	}
}

func TestStatusListenersTCPOnly(t *testing.T) {
	svc, _ := mustBootNamed(t, "tcp-only.yaml")
	st, err := svc.Status(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, l := range st.Listeners {
		got[l.Name] = l.Address
	}
	if got["agent"] != "off" {
		t.Fatalf("udp agent %q", got["agent"])
	}
	if got["agent-tcp"] != ":1161" {
		t.Fatalf("agent-tcp %q", got["agent-tcp"])
	}
	if got["traps-tcp"] != "off" {
		t.Fatalf("traps-tcp %q", got["traps-tcp"])
	}
}

func TestStatusListenersDTLSEnabled(t *testing.T) {
	svc, _ := mustBootNamed(t, "dtls-enabled.yaml")
	st, err := svc.Status(context.Background(), actor())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, l := range st.Listeners {
		got[l.Name] = l.Address
	}
	if got["agent-dtls"] != ":10161" || got["traps-dtls"] != ":10162" {
		t.Fatalf("dtls status: %+v", st.Listeners)
	}
}

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

	trapGen := svc.Traps().Generation()
	res, err := svc.Apply(ctx, a, ChangeIn{
		ExpectedRevision: snap.Revision,
		IdempotencyKey:   "live-admission",
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
	if svc.Traps().Generation() != trapGen {
		t.Fatal("replaceAdmission must not bump trap-store generation")
	}

	_, err = svc.Apply(ctx, a, ChangeIn{
		ExpectedRevision: res.RuntimeRevision,
		IdempotencyKey:   "live-listeners",
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
		IdempotencyKey: "need-rev",
		Operations: []model.Operation{{
			Op:        model.OpReplaceAdmission,
			Admission: &model.AdmissionSpec{AllowClientCidrs: []string{"127.0.0.0/8"}, MaxDatagramsPerSec: 1, MaxDatagramsPerIP: 1},
		}},
	})
	requireCode(t, err, domainerr.CodeValidationFailed)
}

func TestApplyRequiresIdempotencyKey(t *testing.T) {
	svc, snap := mustBoot(t)
	_, err := svc.Apply(context.Background(), actor(), ChangeIn{
		ExpectedRevision: snap.Revision,
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
		IdempotencyKey:   "mismatch",
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

func TestPlanAfterApplyReplaysWithoutEvicting(t *testing.T) {
	svc, snap := mustBoot(t)
	in := ChangeIn{
		ExpectedRevision: snap.Revision,
		IdempotencyKey:   "apply-then-plan",
		Operations: []model.Operation{{
			Op:        model.OpReplaceAdmission,
			Admission: &model.AdmissionSpec{AllowClientCidrs: []string{"127.0.0.0/8", "::1/128"}, MaxDatagramsPerSec: 9, MaxDatagramsPerIP: 3},
		}},
	}
	a := actor()
	r1, err := svc.Apply(context.Background(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.Plan(context.Background(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	if p.CandidateRevision != r1.RuntimeRevision {
		t.Fatalf("plan replay %s want %s", p.CandidateRevision, r1.RuntimeRevision)
	}
	r2, err := svc.Apply(context.Background(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	if r2.RuntimeRevision != r1.RuntimeRevision {
		t.Fatal("plan after apply must not evict the apply record")
	}
}

func TestSetOIDSharesOverlay(t *testing.T) {
	svc, snap := mustBoot(t)
	a := actor()
	oid := "1.3.6.1.2.1.2.2.1.8.1"
	beforeRev := snap.Revision
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
	if svc.Active().Revision != beforeRev {
		t.Fatal("oids:set must not change revision")
	}
	st, err := svc.GetState(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if st.RuntimeRevision != beforeRev {
		t.Fatal("oids:set must not change revision")
	}
}
