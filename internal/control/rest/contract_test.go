package rest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/auth"
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
	s, err := New(Config{
		Service:    svc,
		RatePerSec: -1,
		Metrics:    reg,
		Ready:      func() bool { return true },
		Auth:       auth.Static(testToken, "admin", model.RoleAdministrator),
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("default publicPath false want 401, got %d", w.Code)
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

func TestBearerRequired(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "problem+json") {
		t.Fatalf("ct %s", ct)
	}
	if wa := w.Header().Get("WWW-Authenticate"); !strings.Contains(wa, "Bearer") {
		t.Fatalf("www-authenticate %s", wa)
	}
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), `"code":"unauthenticated"`) {
		t.Fatalf("%s", body)
	}
}

func TestNilVerifierDenies(t *testing.T) {
	svc := bootTestApp(t)
	s, err := New(Config{Service: svc, RatePerSec: -1})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("nil verifier must deny, got %d", w.Code)
	}
}

func TestNoBasic(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("%d", w.Code)
	}
}

func TestCSRFRequiredOnCookieMutation(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/session", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("session create %d %s", w.Code, w.Body.String())
	}
	var cookie string
	for _, c := range w.Result().Cookies() {
		if c.Name == auth.CookieName {
			cookie = c.Value
		}
	}
	var created sessionCreateJSON
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || cookie == "" || created.CSRF == "" {
		t.Fatalf("cookie %q csrf %v err %v", cookie, created, err)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/state:reset", strings.NewReader(`{"reason":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("csrf missing want 403 got %d %s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/state:reset", strings.NewReader(`{"reason":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(auth.CSRFHeader, "not-the-token")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("bad csrf %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/state:reset", strings.NewReader(`{"reason":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(auth.CSRFHeader, created.CSRF)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("csrf ok want 200 got %d %s", w.Code, w.Body.String())
	}
}

func TestAuditAfterReset(t *testing.T) {
	s, _ := newTestServer(t)
	resp := doJSON(t, s, http.MethodPost, "/v1/state:reset", `{"reason":"audit"}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("reset %d %s", resp.StatusCode, b)
	}
	m := decodeMap(t, resp)
	id, _ := m["auditEventId"].(string)
	if id == "" {
		t.Fatalf("auditEventId %v", m)
	}
	list := doJSON(t, s, http.MethodGet, "/v1/audit", "")
	if list.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(list.Body)
		t.Fatalf("audit %d %s", list.StatusCode, b)
	}
	got := decodeMap(t, list)
	events, _ := got["events"].([]any)
	if len(events) == 0 {
		t.Fatal("expected audit events")
	}
	first, _ := events[0].(map[string]any)
	if first["id"] != id || first["capability"] != "state.reset" {
		t.Fatalf("%v", first)
	}
}

func TestUsersListRedacted(t *testing.T) {
	s, _ := newTestServer(t)
	resp := doJSON(t, s, http.MethodGet, "/v1/users", "")
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("users %d %s", resp.StatusCode, b)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"name":"alice"`) {
		t.Fatalf("alice missing: %s", body)
	}
	if !strings.Contains(string(body), "testdata/secrets/snmp-alice-auth") {
		t.Fatalf("secretFile path may appear: %s", body)
	}
	if strings.Contains(string(body), "alice-auth-pass") {
		t.Fatalf("USM secret bytes leaked: %s", body)
	}
	if strings.Contains(string(body), testToken) {
		t.Fatalf("bearer secret leaked: %s", body)
	}
}

func TestOriginExactMatch(t *testing.T) {
	svc := bootTestApp(t)
	s, err := New(Config{
		Service:        svc,
		RatePerSec:     -1,
		Auth:           auth.Static(testToken, "admin", model.RoleAdministrator),
		AllowedOrigins: []string{"https://lab.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("evil origin %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"code":"origin_not_allowed"`) {
		t.Fatalf("%s", w.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Origin", "https://lab.example")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("allowlisted origin %d %s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Origin", "http://127.0.0.1:8088")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("loopback origin %d %s", w.Code, w.Body.String())
	}
}

func TestOriginsFollowReset(t *testing.T) {
	s, _ := newTestServer(t)
	s.sec.Lock()
	s.cfg.AllowedOrigins = []string{"https://lab.example"}
	s.sec.Unlock()
	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Origin", "https://lab.example")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("allowlisted %d %s", w.Code, w.Body.String())
	}
	resp := doJSON(t, s, http.MethodPost, "/v1/state:reset", `{"reason":"origins"}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("reset %d %s", resp.StatusCode, b)
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Origin", "https://lab.example")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("reset must drop origin, got %d %s", w.Code, w.Body.String())
	}
}

func TestPublicMetricsSkipsAuth(t *testing.T) {
	svc := bootTestApp(t)
	snap := svc.Active()
	if _, err := svc.Apply(context.Background(), app.Actor{ID: "test", Class: "test", Transport: "rest", Scopes: model.ScopesForRole(model.RoleAdministrator)}, app.ChangeIn{
		ExpectedRevision: snap.Revision,
		IdempotencyKey:   "obs-skip-auth",
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
	s, err := New(Config{Service: svc, RatePerSec: -1, Auth: auth.Static(testToken, "admin", model.RoleAdministrator)})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusUnauthorized {
		t.Fatal("publicPath metrics must not 401")
	}
	priv := bootTestApp(t)
	s2, err := New(Config{Service: priv, RatePerSec: -1, Auth: auth.Static(testToken, "admin", model.RoleAdministrator)})
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
	w = httptest.NewRecorder()
	s2.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("private metrics %d", w.Code)
	}
}

func TestPublicMetricsFollowsApply(t *testing.T) {
	s, svc := newTestServer(t)
	snap := svc.Active()
	if _, err := svc.Apply(context.Background(), app.Actor{ID: "test", Class: "test", Transport: "rest", Scopes: model.ScopesForRole(model.RoleAdministrator)}, app.ChangeIn{
		ExpectedRevision: snap.Revision,
		IdempotencyKey:   "obs-follow-public",
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
	req := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusUnauthorized {
		t.Fatal("publicPath metrics must not 401")
	}
	st := doJSON(t, s, http.MethodGet, "/v1/state", "")
	if st.StatusCode != http.StatusOK {
		t.Fatal(st.StatusCode)
	}
	rev, _ := decodeMap(t, st)["runtimeRevision"].(string)
	body := `{"expectedRevision":"` + rev + `","idempotencyKey":"obs-public","operations":[{"op":"replaceAdmission","admission":{"allowClientCidrs":["127.0.0.0/8","::1/128"],"maxDatagramsPerSec":1000,"maxDatagramsPerIP":100}}]}`
	resp := doJSON(t, s, http.MethodPost, "/v1/changes:apply", body)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("apply %d %s", resp.StatusCode, b)
	}
	_ = resp.Body.Close()
	req = httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusUnauthorized {
		t.Fatal("unrelated apply must keep live publicPath")
	}
}

func TestMountsRequireBearer(t *testing.T) {
	svc := bootTestApp(t)
	s, err := New(Config{
		Service:    svc,
		RatePerSec: -1,
		Auth:       auth.Static(testToken, "admin", model.RoleAdministrator),
		Mounts:     map[string]http.Handler{"/mcp": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("mount without bearer %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/session", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("session %d", w.Code)
	}
	var cookie string
	for _, c := range w.Result().Cookies() {
		if c.Name == auth.CookieName {
			cookie = c.Value
		}
	}
	req = httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("cookie-only mount %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("bearer mount %d", w.Code)
	}
}

func TestReloadAuthDropsEmptyTokens(t *testing.T) {
	t.Chdir(repoRoot(t))
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "config", "valid", "full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "labsnmp.yaml")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}
	svc, err := app.Boot(context.Background(), app.Options{BootstrapPath: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	s, err := New(Config{Service: svc, RatePerSec: -1, Auth: auth.Static(testToken, "admin", model.RoleAdministrator)})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "config", "valid", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, empty, 0o644); err != nil {
		t.Fatal(err)
	}
	resp := doJSON(t, s, http.MethodPost, "/v1/state:reset", `{"reason":"drop-tokens"}`)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("reset %d %s", resp.StatusCode, b)
	}
	_ = resp.Body.Close()
	req := httptest.NewRequest(http.MethodGet, "/v1/state", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("empty spec.auth must drop old secrets, got %d %s", w.Code, w.Body.String())
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

func TestQueriesListCamelCase(t *testing.T) {
	s, svc := newTestServer(t)
	svc.Queries().Insert(store.Query{Type: "get", Identity: "public", Decision: "ok", ErrorStatus: 0})
	resp := doJSON(t, s, http.MethodGet, "/v1/queries", "")
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("queries %d %s", resp.StatusCode, b)
	}
	m := decodeMap(t, resp)
	items, _ := m["items"].([]any)
	var row map[string]any
	for _, it := range items {
		r, _ := it.(map[string]any)
		if r["identity"] == "public" && r["type"] == "get" {
			row = r
			break
		}
	}
	if row == nil {
		t.Fatalf("missing camelCase query row %v", m)
	}
	if row["decision"] != "ok" {
		t.Fatalf("decision %v", row)
	}
	if _, ok := row["Type"]; ok {
		t.Fatalf("PascalCase Type leaked: %v", row)
	}
	if _, ok := row["errorStatus"]; !ok {
		t.Fatalf("missing errorStatus: %v", row)
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
	digit := doJSON(t, s, http.MethodPost, "/v1/maps/public-if/oids:set", `{"oid":"1.3.6.1.2.1.2.2.1.8.1","value":"3"}`)
	if digit.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(digit.Body)
		t.Fatalf("digit string set %d %s", digit.StatusCode, b)
	}
	_ = digit.Body.Close()
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
	s, err := New(Config{Service: svc, RatePerSec: -1, RequestTimeout: 40 * time.Millisecond, Auth: auth.Static(testToken, "admin", model.RoleAdministrator)})
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
	req.Header.Set("Authorization", "Bearer "+testToken)
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
	req.Header.Set("Authorization", "Bearer "+testToken)
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
