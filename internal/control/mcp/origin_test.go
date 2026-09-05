package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func TestOriginsFollowReset(t *testing.T) {
	s, svc := newTestServer(t)
	s.sec.Lock()
	s.cfg.AllowedOrigins = []string{"https://lab.example"}
	s.sec.Unlock()
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+testBearerToken)
	req.Header.Set("Origin", "https://lab.example")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code == http.StatusForbidden {
		t.Fatalf("allowlisted origin rejected: %s", w.Body.String())
	}
	actor := app.Actor{
		ID: "admin", Class: "token", Role: model.RoleAdministrator,
		Scopes: model.ScopesForRole(model.RoleAdministrator), Transport: "mcp",
	}
	if _, err := svc.Reset(t.Context(), actor, app.ResetIn{Reason: "origins"}); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Authorization", "Bearer "+testBearerToken)
	req.Header.Set("Origin", "https://lab.example")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("reset must drop origin, got %d %s", w.Code, w.Body.String())
	}
}

func TestAllowLegacyClientsFollowsReset(t *testing.T) {
	s, svc := newPinnedServer(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"legacy-gateway","version":"0.0.1"}}}`
	rec := doRaw(t, s.Handler(), body, map[string]string{
		"Content-Type":        "application/json",
		"Accept":              "application/json, text/event-stream",
		headerProtocolVersion: "2025-03-26",
		"Authorization":       "Bearer " + testBearerToken,
	}, "127.0.0.1:1")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("pinned must reject legacy header, got %d %s", rec.Code, rec.Body.String())
	}
	actor := app.Actor{
		ID: "admin", Class: "token", Role: model.RoleAdministrator,
		Scopes: model.ScopesForRole(model.RoleAdministrator), Transport: "mcp",
	}
	if _, err := svc.Reset(t.Context(), actor, app.ResetIn{Reason: "legacy"}); err != nil {
		t.Fatal(err)
	}
	rec2 := doRaw(t, s.Handler(), body, map[string]string{
		"Content-Type":        "application/json",
		"Accept":              "application/json, text/event-stream",
		headerProtocolVersion: "2025-03-26",
		"Authorization":       "Bearer " + testBearerToken,
	}, "127.0.0.1:1")
	if rec2.Code == http.StatusBadRequest {
		t.Fatalf("reset overlay allowLegacyClients must accept header: %s", rec2.Body.String())
	}
}
