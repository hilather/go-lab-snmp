package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
