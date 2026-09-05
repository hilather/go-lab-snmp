package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestStaticBearer(t *testing.T) {
	v := Static(testSecret, "admin", model.RoleAdministrator)
	if err := v.RequireListen(); err != nil {
		t.Fatal(err)
	}
	p, err := v.Authenticate(Request{Authorization: "Bearer " + testSecret})
	if err != nil || p.ID != "admin" {
		t.Fatalf("%+v %v", p, err)
	}
	if !p.HasScope(model.ScopeSNMPAdmin) {
		t.Fatal("admin scopes")
	}
	_, err = v.Authenticate(Request{Authorization: "Basic dXNlcjpwYXNz"})
	if err == nil {
		t.Fatal("Basic must 401")
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeUnauthenticated {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(WWWAuthenticate()[0], "Bearer") {
		t.Fatal(WWWAuthenticate())
	}
}

func TestReaderScopes(t *testing.T) {
	v := Static(testSecret, "reader", model.RoleReader)
	p, err := v.Authenticate(Request{Authorization: "Bearer " + testSecret})
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasScope(model.ScopeSNMPRead) {
		t.Fatal("reader read")
	}
	if p.HasScope(model.ScopeSNMPWrite) || p.HasScope(model.ScopeSNMPAdmin) {
		t.Fatal("reader must not write/admin")
	}
}

func TestFromSpecFileRefAndMinBytes(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(short, []byte("tooshort\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := FromSpec(model.AuthSpec{
		Mode: model.MgmtAuthBearer,
		Tokens: []model.TokenSpec{{
			ID: "admin", Role: model.RoleAdministrator, SecretFile: short,
		}},
	})
	if err == nil {
		t.Fatal("short token")
	}
	okPath := filepath.Join(dir, "ok")
	if err := os.WriteFile(okPath, []byte(testSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := FromSpec(model.AuthSpec{
		Mode: model.MgmtAuthBearer,
		Tokens: []model.TokenSpec{{
			ID: "admin", Role: model.RoleAdministrator, SecretFile: okPath,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.TokenCount() != 1 {
		t.Fatal(v.TokenCount())
	}
}

func TestZeroTokensRefuseListen(t *testing.T) {
	v, err := FromSpec(model.AuthSpec{Mode: model.MgmtAuthBearer})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.RequireListen(); err == nil {
		t.Fatal("zero tokens must fail closed")
	}
}

func TestMissingAuthUnauthenticated(t *testing.T) {
	v := Static(testSecret, "admin", model.RoleAdministrator)
	_, err := v.Authenticate(Request{})
	if err == nil {
		t.Fatal("missing")
	}
}

func TestUnknownModeRejected(t *testing.T) {
	_, err := FromSpec(model.AuthSpec{Mode: "basic"})
	if err == nil {
		t.Fatal("basic")
	}
}

func TestFromSpecEmptyRoleRejected(t *testing.T) {
	dir := t.TempDir()
	okPath := filepath.Join(dir, "ok")
	if err := os.WriteFile(okPath, []byte(testSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := FromSpec(model.AuthSpec{
		Mode: model.MgmtAuthBearer,
		Tokens: []model.TokenSpec{{
			ID: "admin", SecretFile: okPath,
		}},
	})
	if err == nil {
		t.Fatal("empty role must fail closed")
	}
}

func TestFromSpecAtResolvesBaseDir(t *testing.T) {
	dir := t.TempDir()
	name := "labsnmp-fromspec-token"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(testSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec := model.AuthSpec{
		Mode: model.MgmtAuthBearer,
		Tokens: []model.TokenSpec{{
			ID: "admin", Role: model.RoleAdministrator, SecretFile: name,
		}},
	}
	if _, err := FromSpec(spec); err == nil {
		t.Fatal("CWD-only must not see bootstrap-dir secret")
	}
	v, err := FromSpecAt(spec, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Authenticate(Request{Authorization: "Bearer " + testSecret}); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyDenies(t *testing.T) {
	v := Empty()
	if err := v.RequireListen(); err == nil {
		t.Fatal("empty must refuse listen")
	}
	if _, err := v.Authenticate(Request{Authorization: "Bearer " + testSecret}); err == nil {
		t.Fatal("empty must 401")
	}
}
