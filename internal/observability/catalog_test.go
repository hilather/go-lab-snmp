package observability

import (
	"strings"
	"testing"
)

func TestCatalogNoClientIPLabels(t *testing.T) {
	for _, m := range Metrics() {
		for _, l := range m.Labels {
			if ForbiddenLabel(l) || strings.Contains(strings.ToLower(l), "ip") {
				t.Errorf("metric %s has forbidden label %s", m.Name, l)
			}
			if strings.Contains(strings.ToLower(l), "secret") || strings.Contains(strings.ToLower(l), "community") {
				t.Errorf("metric %s has secret label %s", m.Name, l)
			}
		}
	}
	for _, f := range ForbiddenLabels {
		if f == "client_ip" {
			goto haveIP
		}
	}
	t.Fatal("ForbiddenLabels must include client_ip")
haveIP:
	for _, f := range ForbiddenLabels {
		if f == "community" {
			return
		}
	}
	t.Fatal("ForbiddenLabels must include community")
}

func TestCatalogSeriesNames(t *testing.T) {
	want := []string{
		MetricPDUsTotal, MetricTrapsTotal, MetricStoreMessages, MetricStoreBytes,
		MetricApplyTotal, MetricHTTPRequestsTotal, MetricBuildInfo, MetricAuthFailTotal,
	}
	have := map[string]bool{}
	for _, m := range Metrics() {
		have[m.Name] = true
	}
	for _, n := range want {
		if !have[n] {
			t.Errorf("missing series %s", n)
		}
	}
}

func TestRegistryOpenMetrics(t *testing.T) {
	r := NewRegistry()
	r.Inc(MetricPDUsTotal, map[string]string{"version": "v2c", "pdu": "get", "decision": "ok"}, 1)
	r.Inc(MetricPDUsTotal, map[string]string{"version": "v1", "pdu": "get", "decision": "auth_fail"}, 2)
	r.Inc(MetricAuthFailTotal, map[string]string{"version": "v1"}, 2)
	r.Inc(MetricTrapsTotal, map[string]string{"version": "v2c", "decision": "ok"}, 1)
	r.Set(MetricStoreMessages, nil, 3)
	r.Set(MetricStoreBytes, nil, 128)
	r.Set(MetricBuildInfo, map[string]string{"version": "dev", "commit": "abc"}, 1)
	r.Inc(MetricHTTPRequestsTotal, map[string]string{"code": "200", "route": "/v1/health/ready"}, 1)
	r.Inc(MetricPDUsTotal, map[string]string{"version": "v2c", "pdu": "get", "decision": "ok", "client_ip": "1.2.3.4"}, 1)
	var b strings.Builder
	if err := r.WriteOpenMetrics(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "labsnmp_pdus_total") {
		t.Fatal(out)
	}
	if !strings.Contains(out, `decision="ok"`) {
		t.Fatal(out)
	}
	if !strings.Contains(out, "labsnmp_auth_fail_total") {
		t.Fatal(out)
	}
	if !strings.HasSuffix(out, "# EOF\n") {
		t.Fatal(out)
	}
	if strings.Contains(out, "client_ip") {
		t.Fatal("client IP leaked into scrape")
	}
	if strings.Contains(out, "community") {
		t.Fatal("community leaked into scrape")
	}
}

func TestForbiddenLabelsDropped(t *testing.T) {
	r := NewRegistry()
	r.Inc(MetricPDUsTotal, map[string]string{"version": "v2c", "pdu": "get", "decision": "ok", "client_ip": "10.0.0.1"}, 1)
	if r.Dropped() < 1 {
		t.Fatal("forbidden label must drop")
	}
	if _, ok := r.Get(MetricPDUsTotal, map[string]string{"version": "v2c", "pdu": "get", "decision": "ok"}); ok {
		t.Fatal("forbidden sample must not be recorded")
	}
}

func TestEvaluateReady(t *testing.T) {
	p := Evaluate(Facts{AgentBound: true, TrapOff: true, SnapshotUp: true, MgmtOff: true})
	if !p.Live || !p.Ready {
		t.Fatalf("%+v", p)
	}
	p = Evaluate(Facts{AgentBound: true, TrapOff: true, SnapshotUp: true})
	if p.Ready {
		t.Fatal("mgmt unbound should not be ready")
	}
	p = Evaluate(Facts{AgentBound: true, SnapshotUp: true, MgmtOff: true})
	if p.Ready {
		t.Fatal("trap unbound should not be ready after TRAP-001")
	}
	p = Evaluate(Facts{AgentBound: true, TrapBound: true, SnapshotUp: true, MgmtBound: true})
	if !p.Ready {
		t.Fatalf("%+v", p)
	}
	p = Evaluate(Facts{AgentOff: true, TrapOff: true, SnapshotUp: true, MgmtOff: true})
	if !p.Ready {
		t.Fatal("disabled listeners are ready")
	}
	p = Evaluate(Facts{AgentBound: true, TrapOff: true, MgmtOff: true})
	if p.Ready {
		t.Fatal("missing snapshot")
	}
	p = Evaluate(Facts{SnapshotUp: true})
	if p.Ready {
		t.Fatal("fail-closed without listener facts")
	}
}

func TestLabelHelpers(t *testing.T) {
	if PDUDecision("ok") != "ok" || PDUDecision("serve") != "ok" {
		t.Fatal("pdu decision")
	}
	if PDUType("getNext") != "getnext" {
		t.Fatal("pdu type")
	}
	if SNMPVersion("v2c") != "v2c" {
		t.Fatal("version")
	}
	if HTTPCode(200) != "200" || HTTPRoute("/v1/health/ready") != "/v1/health/ready" {
		t.Fatal("http")
	}
	if HTTPRoute("") != "other" {
		t.Fatal("other")
	}
	if TrapDecision("stored") != "ok" {
		t.Fatal("trap")
	}
}
