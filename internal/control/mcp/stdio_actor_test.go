package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
		StdioSecret:        testBearerToken,
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

// TestStdioFixedActorFollowsTokenDemotion asserts mcp-stdio re-authenticates
// its startup bearer on each call. A demotion of that secret to reader drops
// snmp.admin on the next call and keeps snmp.read. The startup FixedActor
// value is not rewritten.
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
	if fixed.Role != model.RoleAdministrator || fixed.ID != "admin" {
		t.Fatalf("FixedActor was mutated: %+v", fixed)
	}
	if s.cfg.FixedActor == nil || s.cfg.FixedActor.ID != "admin" || s.cfg.FixedActor.Role != model.RoleAdministrator || !hasScope(s.cfg.FixedActor.Scopes, model.ScopeSNMPAdmin) {
		t.Fatalf("stored FixedActor was mutated: %+v", s.cfg.FixedActor)
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
// drops every token denies every scoped tool. The startup secret no
// longer authenticates, so the stdio process has no actor.
func TestStdioFixedActorLosesAccessWhenTokenRemoved(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		s, verifier, _ := newPinnedAdmin(t)
		verifier.Replace(auth.Empty())
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

// TestStdioFixedActorFollowsLiveSecretIdentity asserts the stdio process
// acts as whatever principal the startup secret authenticates as now.
// The same secret under a new id is that new principal, not a denial
// and not the startup id.
func TestStdioFixedActorFollowsLiveSecretIdentity(t *testing.T) {
	s, verifier, fixed := newPinnedAdmin(t)
	verifier.Replace(auth.Static(testBearerToken, "other", model.RoleAdministrator))
	actor := s.actorFrom(context.Background())
	if actor.ID != "other" || actor.Role != model.RoleAdministrator {
		t.Fatalf("stdio actor = %+v, want id other role administrator", actor)
	}
	if err := s.authorizeTool(actor, "snmp_state_reset"); err != nil {
		t.Fatalf("same secret under id other must keep snmp_state_reset: %v", err)
	}
	if !hasScope(actor.Scopes, model.ScopeSNMPAdmin) {
		t.Fatalf("scopes = %v, want snmp.admin", actor.Scopes)
	}
	if fixed.ID != "admin" || fixed.Role != model.RoleAdministrator {
		t.Fatalf("FixedActor was mutated: %+v", fixed)
	}
	if s.cfg.FixedActor == nil || s.cfg.FixedActor.ID != "admin" || s.cfg.FixedActor.Role != model.RoleAdministrator || !hasScope(s.cfg.FixedActor.Scopes, model.ScopeSNMPAdmin) {
		t.Fatalf("stored FixedActor was mutated: %+v", s.cfg.FixedActor)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	got, err := s.authenticate(req)
	if err != nil || got.ID != "other" || got.Role != model.RoleAdministrator {
		t.Fatalf("empty-header authenticate = %+v err=%v, want other administrator", got, err)
	}
}

// TestStdioFixedActorLosesAccessAfterSameIDSecretRotation asserts the
// standard revocation step: same id, new secret. The old secret no longer
// authenticates, and the stdio process loses snmp.admin.
func TestStdioFixedActorLosesAccessAfterSameIDSecretRotation(t *testing.T) {
	s, verifier, fixed := newPinnedAdmin(t)
	if err := s.authorizeTool(s.actorFrom(context.Background()), "snmp_state_reset"); err != nil {
		t.Fatal(err)
	}
	rotated := strings.Repeat("n", len(testBearerToken))
	verifier.Replace(auth.Static(rotated, "admin", model.RoleAdministrator))
	if _, err := verifier.AuthenticateBearer(testBearerToken); err == nil {
		t.Fatal("old secret still authenticates after same-id rotation")
	}
	actor := s.actorFrom(context.Background())
	if err := s.authorizeTool(actor, "snmp_state_reset"); err == nil {
		t.Fatalf("stdio still authorized for snmp_state_reset after the secret rotated (same id), actor=%+v", actor)
	}
	if err := s.authorizeTool(actor, "snmp_version_get"); err == nil {
		t.Fatalf("stdio still authorized for snmp_version_get after the secret rotated (same id), actor=%+v", actor)
	}
	if fixed.ID != "admin" || fixed.Role != model.RoleAdministrator {
		t.Fatalf("FixedActor was mutated: %+v", fixed)
	}
	if s.cfg.FixedActor == nil || s.cfg.FixedActor.ID != "admin" || s.cfg.FixedActor.Role != model.RoleAdministrator || !hasScope(s.cfg.FixedActor.Scopes, model.ScopeSNMPAdmin) {
		t.Fatalf("stored FixedActor was mutated: %+v", s.cfg.FixedActor)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	_, err := s.authenticate(req)
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeUnauthenticated {
		t.Fatalf("empty-header authenticate err=%v want unauthenticated", err)
	}
}

// TestStdioFixedActorRestoredWhenOriginalSecretReturns asserts that putting
// the startup secret back, after a same-id rotation, restores the actor.
func TestStdioFixedActorRestoredWhenOriginalSecretReturns(t *testing.T) {
	s, verifier, _ := newPinnedAdmin(t)
	rotated := strings.Repeat("n", len(testBearerToken))
	verifier.Replace(auth.Static(rotated, "admin", model.RoleAdministrator))
	if err := s.authorizeTool(s.actorFrom(context.Background()), "snmp_state_reset"); err == nil {
		t.Fatal("stdio still authorized for snmp_state_reset after the secret rotated (same id)")
	}
	verifier.Replace(auth.Static(testBearerToken, "admin", model.RoleAdministrator))
	if _, err := verifier.AuthenticateBearer(testBearerToken); err != nil {
		t.Fatal("original secret did not authenticate after restore")
	}
	actor := s.actorFrom(context.Background())
	if err := s.authorizeTool(actor, "snmp_state_reset"); err != nil {
		t.Fatalf("original secret did not restore snmp_state_reset: %v actor=%+v", err, actor)
	}
	if actor.ID != "admin" || actor.Role != model.RoleAdministrator {
		t.Fatalf("restored actor = %+v, want admin administrator", actor)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	got, err := s.authenticate(req)
	if err != nil || got.ID != "admin" || got.Role != model.RoleAdministrator {
		t.Fatalf("empty-header authenticate = %+v err=%v, want admin administrator", got, err)
	}
}

func TestNewRejectsFixedActorWithoutStdioSecret(t *testing.T) {
	svc := bootTestApp(t)
	fixed := app.Actor{
		ID: "admin", Class: "token", Role: model.RoleAdministrator,
		Scopes: model.ScopesForRole(model.RoleAdministrator), Transport: "mcp",
	}
	_, err := New(Config{
		Service:            svc,
		Auth:               auth.Static(testBearerToken, "admin", model.RoleAdministrator),
		FixedActor:         &fixed,
		AllowLegacyClients: true,
		RatePerSec:         -1,
	})
	if err == nil {
		t.Fatal("New accepted FixedActor without StdioSecret")
	}
	if strings.Contains(err.Error(), testBearerToken) {
		t.Fatal("New error included the bearer secret")
	}
	if err.Error() != "mcp: StdioSecret is required when FixedActor is set" {
		t.Fatalf("New err = %v", err)
	}
}

func TestNewRejectsStdioSecretWithoutAuth(t *testing.T) {
	svc := bootTestApp(t)
	_, err := New(Config{
		Service:     svc,
		StdioSecret: testBearerToken,
		RatePerSec:  -1,
	})
	if err == nil {
		t.Fatal("New accepted StdioSecret without Auth")
	}
	if strings.Contains(err.Error(), testBearerToken) {
		t.Fatal("New error included the bearer secret")
	}
	if err.Error() != "mcp: Auth is required when StdioSecret is set" {
		t.Fatalf("New err = %v", err)
	}
}

func TestNewAllowsFixedActorWithoutAuthOrSecret(t *testing.T) {
	svc := bootTestApp(t)
	fixed := app.Actor{
		ID: "dev", Class: "token", Role: model.RoleAdministrator,
		Scopes: model.ScopesForRole(model.RoleAdministrator), Transport: "mcp",
	}
	s, err := New(Config{
		Service: svc, FixedActor: &fixed,
		AllowLegacyClients: true, RatePerSec: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	actor := s.actorFrom(context.Background())
	if actor.ID != "dev" || actor.Role != model.RoleAdministrator {
		t.Fatalf("no-auth stdio actor = %+v, want dev administrator", actor)
	}
	if s.cfg.FixedActor == nil || s.cfg.FixedActor.ID != "dev" {
		t.Fatalf("stored FixedActor = %+v", s.cfg.FixedActor)
	}
}
