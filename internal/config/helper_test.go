package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
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

func testdata(t *testing.T, elem ...string) string {
	t.Helper()
	parts := append([]string{repoRoot(t), "testdata", "config"}, elem...)
	return filepath.Join(parts...)
}

func mustLoad(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(testdata(t, rel...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func requireValidation(t *testing.T, err error, codes ...string) *domainerr.Error {
	t.Helper()
	if err == nil {
		t.Fatal("expected validation error")
	}
	de, ok := domainerr.As(err)
	if !ok {
		t.Fatalf("error is %T %v, want *domainerr.Error", err, err)
	}
	if len(codes) == 0 {
		return de
	}
	have := map[string]bool{string(de.Code): true}
	for _, v := range de.FieldViolations {
		have[v.Code] = true
	}
	for _, c := range codes {
		if !have[c] {
			t.Fatalf("missing code %q in domain=%s violations=%+v", c, de.Code, de.FieldViolations)
		}
	}
	return de
}
