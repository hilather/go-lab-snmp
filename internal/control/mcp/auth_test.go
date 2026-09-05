package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/auth"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func TestBearerRequired(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d body=%s", w.Code, w.Body.String())
	}
}

func TestNoBasic(t *testing.T) {
	s, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d", w.Code)
	}
}

func TestNilVerifierDenies(t *testing.T) {
	svc := bootTestApp(t)
	s, err := New(Config{Service: svc, RatePerSec: -1, AllowLegacyClients: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+testBearerToken)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("nil verifier must deny, got %d", w.Code)
	}
}

func TestReaderForbiddenOnMutations(t *testing.T) {
	svc := bootTestApp(t)
	s, err := New(Config{
		Service:            svc,
		RatePerSec:         -1,
		AllowLegacyClients: true,
		Auth:               auth.Static(testReaderToken, "reader", model.RoleReader),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	ts := startHTTP(t, s)
	cs := connectClientAuth(t, ts, testReaderToken)
	ver := callTool(t, cs, "snmp_version_get", map[string]any{})
	if ver.IsError {
		t.Fatalf("reader version: %+v", ver)
	}
	for _, name := range []string{"snmp_oid_set", "snmp_change_apply", "snmp_state_reset"} {
		args := map[string]any{}
		if name == "snmp_oid_set" {
			args = map[string]any{"name": "public-if", "oid": "1.3.6.1.2.1.2.2.1.8.1", "value": 2}
		}
		res := callTool(t, cs, name, args)
		if code := toolErrorCode(t, res); code != "forbidden" {
			t.Fatalf("%s code=%s", name, code)
		}
	}
}

func TestUnknownToolForbidden(t *testing.T) {
	s, _ := newTestServer(t)
	actor := app.Actor{
		ID: "admin", Class: "token", Role: model.RoleAdministrator,
		Scopes: model.ScopesForRole(model.RoleAdministrator), Transport: "mcp",
	}
	if err := s.authorizeTool(actor, "snmp_not_a_tool"); err == nil {
		t.Fatal("unknown tool must be forbidden")
	}
}
