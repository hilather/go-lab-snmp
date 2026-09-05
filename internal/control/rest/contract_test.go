package rest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/capabilities"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/store"
)

func TestMetricsPublicPath(t *testing.T) {
	svc := bootTestApp(t)
	reg := observability.NewRegistry()
	reg.Inc(observability.MetricPDUsTotal, map[string]string{"version": "v2c", "pdu": "get", "decision": "ok"}, 1)
	s, err := New(Config{Service: svc, RatePerSec: -1, Metrics: reg, Ready: func() bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("default publicPath false want 404, got %d", w.Code)
	}

	snap := svc.Active()
	if _, err := svc.Apply(context.Background(), app.Actor{ID: "test", Class: "test", Transport: "rest", Scopes: model.ScopesForRole(model.RoleAdministrator)}, app.ChangeIn{
		ExpectedRevision: snap.Revision,
		IdempotencyKey:   "obs-public",
		Operations: []model.Operation{{
			Op: model.OpReplaceObservability,
			Observability: &model.ObservabilitySpec{
				LogLevel: model.LogLevelInfo,
				Metrics:  model.MetricsSpec{PublicPath: true},
			},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("live publicPath true %d %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "openmetrics") {
		t.Fatalf("content-type %s", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "labsnmp_pdus_total") || !strings.HasSuffix(body, "# EOF\n") {
		t.Fatal(body)
	}
	if strings.Contains(body, "client_ip") {
		t.Fatal("client IP in scrape")
	}
}

func TestHealthReadyNotReady(t *testing.T) {
	svc := bootTestApp(t)
	s, err := New(Config{Service: svc, RatePerSec: -1, Ready: func() bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready %d", w.Code)
	}
}

func TestHealthUnauthenticated(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/health/live", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("live %d body=%s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ready %d body=%s", w.Code, w.Body.String())
	}
}

func TestV1UnauthenticatedStub(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/version", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("auth stub must not 401, got %d", w.Code)
	}
}

func TestProblemJSONCode(t *testing.T) {
	p := capabilities.ProblemFrom(domainerr.ValidationFailed("x"), "urn:labsnmp:request:1")
	if p.Status != 400 || p.Code != domainerr.CodeValidationFailed {
		t.Fatalf("%+v", p)
	}
	if p.Type != "urn:labsnmp:error:validation-failed" {
		t.Fatalf("type %s", p.Type)
	}
}

func TestFeaturesCatalogK20(t *testing.T) {
	s, _ := newTestServer(t)
	resp := doJSON(t, s, http.MethodGet, "/v1/features", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	m := decodeMap(t, resp)
	items, _ := m["items"].([]any)
	if len(items) != len(capabilities.Features()) {
		t.Fatalf("features %d want %d", len(items), len(capabilities.Features()))
	}
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		id, _ := item["id"].(string)
		if id == "ui.enabled" || id == "dtls" || id == "tcp" {
			t.Fatalf("invented feature id %s", id)
		}
	}
}

func TestMapQueryContract(t *testing.T) {
	s, _ := newTestServer(t)
	resp := doJSON(t, s, http.MethodPost, "/v1/maps/public-if:query", `{"pdu":"get","oids":["1.3.6.1.2.1.1.1.0"]}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("query %d %s", resp.StatusCode, b)
	}
	m := decodeMap(t, resp)
	bindings, _ := m["bindings"].([]any)
	if len(bindings) != 1 {
		t.Fatalf("bindings %v", m)
	}
	b0, _ := bindings[0].(map[string]any)
	if b0["value"] != "LabSNMP public-if" {
		t.Fatalf("value %v", b0)
	}
	resp = doJSON(t, s, http.MethodPost, "/v1/maps/public-if:query", `{"pdu":"getNext","oids":["1.3.6.1.2.1.1.1.0"]}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("getNext %d %s", resp.StatusCode, b)
	}
}

func TestOIDSetContract(t *testing.T) {
	s, _ := newTestServer(t)
	resp := doJSON(t, s, http.MethodPost, "/v1/maps/public-if/oids:set", `{"oid":"1.3.6.1.2.1.2.2.1.8.1","value":2}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("set %d %s", resp.StatusCode, b)
	}
	m := decodeMap(t, resp)
	if m["overlay"] != true {
		t.Fatalf("overlay %v", m)
	}
	got := doJSON(t, s, http.MethodPost, "/v1/maps/public-if/oids:get", `{"oid":"1.3.6.1.2.1.2.2.1.8.1"}`)
	if got.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(got.Body)
		t.Fatalf("get %d %s", got.StatusCode, b)
	}
	gm := decodeMap(t, got)
	if gm["overlay"] != true {
		t.Fatalf("get overlay %v", gm)
	}
	bad := doJSON(t, s, http.MethodPost, "/v1/maps/public-if/oids:set", `{"oid":"1.3.6.1.2.1.2.2.1.8.1","value":2,"extra":true}`)
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("extra field %d", bad.StatusCode)
	}
	body, _ := io.ReadAll(bad.Body)
	if !strings.Contains(string(body), `"code":"unknown_field"`) && !strings.Contains(string(body), `"code":"validation_failed"`) {
		t.Fatalf("extra field body %s", body)
	}
}

func TestTrapsWaitContract(t *testing.T) {
	s, svc := newTestServer(t)
	id, err := svc.Traps().Insert(store.TrapRecord{
		Version:         "v2c",
		PDUType:         "trapv2",
		Community:       "public",
		NotificationOID: "1.3.6.1.6.3.1.1.5.1",
		ReceivedAt:      time.Now().UTC(),
		Raw:             []byte{0x30, 0x00},
	})
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("id")
	}
	resp := doJSON(t, s, http.MethodPost, "/v1/traps:wait", `{"timeout":"2s","community":"public"}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("wait %d %s", resp.StatusCode, b)
	}
	m := decodeMap(t, resp)
	if m["id"] != id {
		t.Fatalf("wait id %v want %s", m["id"], id)
	}
	svc.Traps().Clear()
	miss := doJSON(t, s, http.MethodPost, "/v1/traps:wait", `{"timeout":"50ms"}`)
	if miss.StatusCode != http.StatusGatewayTimeout {
		b, _ := io.ReadAll(miss.Body)
		t.Fatalf("timeout %d %s", miss.StatusCode, b)
	}
	body, _ := io.ReadAll(miss.Body)
	if !strings.Contains(string(body), `"code":"wait_timeout"`) {
		t.Fatalf("timeout body %s", body)
	}
}

func TestTrapsWaitSkipsGenericRequestTimeout(t *testing.T) {
	svc := bootTestApp(t)
	s, err := New(Config{Service: svc, RatePerSec: -1, RequestTimeout: 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *http.Response, 1)
	go func() {
		done <- doJSON(t, s, http.MethodPost, "/v1/traps:wait", `{"timeout":"500ms"}`)
	}()
	time.Sleep(80 * time.Millisecond)
	id, err := svc.Traps().Insert(store.TrapRecord{
		Version:         "v2c",
		PDUType:         "trapv2",
		Community:       "public",
		NotificationOID: "1.3.6.1.6.3.1.1.5.1",
		ReceivedAt:      time.Now().UTC(),
		Raw:             []byte{0x30, 0x00},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp := <-done
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("wait must outlive request timeout, got %d %s", resp.StatusCode, b)
	}
	m := decodeMap(t, resp)
	if m["id"] != id {
		t.Fatalf("wait id %v want %s", m["id"], id)
	}
}

func TestStateExportYAMLContract(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/state:export", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("export %d %s", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "yaml") {
		t.Fatalf("content-type %s", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "apiVersion: labsnmp.dev/v1alpha1") {
		t.Fatalf("yaml %s", body)
	}
	if !strings.Contains(body, "kind: LabSNMP") {
		t.Fatalf("kind %s", body)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/state:export?format=json", nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("export json %d %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "json") || strings.Contains(ct, "problem+json") {
		t.Fatalf("json content-type %s", ct)
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["apiVersion"] != "labsnmp.dev/v1alpha1" || doc["kind"] != "LabSNMP" {
		t.Fatalf("json envelope leaked: %v", doc)
	}
	if _, ok := doc["body"]; ok {
		t.Fatalf("json export must be the canonical document, not an envelope: %v", doc)
	}
}

func TestPreviewAndRoot404(t *testing.T) {
	s, _ := newTestServer(t)
	resp := doJSON(t, s, http.MethodGet, "/v1/preview/get?community=public&oid=1.3.6.1.2.1.1.1.0", "")
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("preview %d %s", resp.StatusCode, b)
	}
	m := decodeMap(t, resp)
	if m["value"] != "LabSNMP public-if" {
		t.Fatalf("preview %v", m)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET / %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "problem+json") {
		t.Fatalf("ct %s", ct)
	}
}
