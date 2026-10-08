package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/auth"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func newPinnedAdmin(t *testing.T) (*Server, *auth.Verifier, app.Actor) {
	t.Helper()
	svc := bootTestApp(t)
	verifier := auth.Static(testBearerToken, "admin", model.RoleAdministrator)
	p, err := verifier.AuthenticateBearer(testBearerToken)
	if err != nil {
		t.Fatal(err)
	}
	fixed := app.Actor{
		ID: p.ID, Class: p.Class, Role: p.Role,
		Scopes: append([]string(nil), p.Scopes...), Transport: "mcp",
	}
	s, err := New(Config{
		Service: svc, Auth: verifier, FixedActor: &fixed,
		AllowLegacyClients: true, RatePerSec: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, verifier, fixed
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// TestStdioFixedActorFollowsTokenDemotion asserts mcp-stdio re-reads the
// pinned token id from the live verifier. A demotion to reader drops
// snmp.admin on the next call and keeps snmp.read.
func TestStdioFixedActorFollowsTokenDemotion(t *testing.T) {
	s, verifier, fixed := newPinnedAdmin(t)
	if err := s.authorizeTool(s.actorFrom(context.Background()), "snmp_state_reset"); err != nil {
		t.Fatal(err)
	}
	verifier.Replace(auth.Static(testBearerToken, "admin", model.RoleReader))
	actor := s.actorFrom(context.Background())
	err := s.authorizeTool(actor, "snmp_state_reset")
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeForbidden {
		t.Fatalf("stdio actor still authorized for snmp_state_reset after demotion, scopes=%v err=%v", actor.Scopes, err)
	}
	if actor.Role != model.RoleReader {
		t.Fatalf("role=%q want reader", actor.Role)
	}
	if hasScope(actor.Scopes, model.ScopeSNMPAdmin) {
		t.Fatalf("scopes include snmp.admin after demotion: %v", actor.Scopes)
	}
	if err := s.authorizeTool(actor, "snmp_version_get"); err != nil {
		t.Fatalf("reader must keep snmp_version_get: %v", err)
	}
	if fixed.Role != model.RoleAdministrator {
		t.Fatalf("FixedActor was mutated: %+v", fixed)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	got, err := s.authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Role != model.RoleReader || got.ID != "admin" {
		t.Fatalf("empty-header authenticate = %+v, want reader admin", got)
	}
	if hasScope(got.Scopes, model.ScopeSNMPAdmin) {
		t.Fatalf("authenticate scopes include snmp.admin: %v", got.Scopes)
	}
}

// TestStdioFixedActorLosesAccessWhenTokenRemoved asserts a reset that
// drops the startup token id denies every scoped tool.
func TestStdioFixedActorLosesAccessWhenTokenRemoved(t *testing.T) {
	for _, tc := range []struct {
		name string
		next *auth.Verifier
	}{
		{name: "other-id", next: auth.Static(testBearerToken, "other", model.RoleAdministrator)},
		{name: "empty", next: auth.Empty()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, verifier, _ := newPinnedAdmin(t)
			verifier.Replace(tc.next)
			actor := s.actorFrom(context.Background())
			if err := s.authorizeTool(actor, "snmp_state_reset"); err == nil {
				t.Fatalf("removed token still authorized snmp_state_reset, actor=%+v", actor)
			}
			if err := s.authorizeTool(actor, "snmp_version_get"); err == nil {
				t.Fatalf("removed token still authorized snmp_version_get, actor=%+v", actor)
			}
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			_, err := s.authenticate(req)
			de, ok := domainerr.As(err)
			if !ok || de.Code != domainerr.CodeUnauthenticated {
				t.Fatalf("empty-header authenticate err=%v want unauthenticated", err)
			}
		})
	}
}
