package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func copyFull(t *testing.T) string {
	t.Helper()
	t.Chdir(repoRoot(t))
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "config", "valid", "full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "labsnmp.yaml")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustBoot(t *testing.T) (*App, *snapshot.Snapshot) {
	t.Helper()
	return mustBootNamed(t, "full.yaml")
}

func mustBootNamed(t *testing.T, name string) (*App, *snapshot.Snapshot) {
	t.Helper()
	t.Chdir(repoRoot(t))
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "config", "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "labsnmp.yaml")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}
	svc, err := Boot(context.Background(), Options{BootstrapPath: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	snap := svc.Active()
	if snap == nil {
		t.Fatal("no snapshot")
	}
	return svc, snap
}

func copyNamed(t *testing.T, name string) string {
	t.Helper()
	t.Chdir(repoRoot(t))
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "config", "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "labsnmp.yaml")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func actor() Actor {
	return Actor{ID: "test", Class: "test", Transport: "direct", Scopes: model.ScopesForRole(model.RoleAdministrator)}
}

func requireCode(t *testing.T, err error, code domainerr.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s", code)
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != code {
		t.Fatalf("err=%v want %s", err, code)
	}
}
