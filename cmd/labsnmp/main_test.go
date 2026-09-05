package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/config"
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

func TestVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labsnmp", "version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d, stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "labsnmp") {
		t.Fatalf("version output %q missing labsnmp", stdout.String())
	}
	if !strings.Contains(stdout.String(), "labsnmp.dev/v1alpha1") {
		t.Fatalf("version %q missing config API", stdout.String())
	}
	if !strings.Contains(stdout.String(), "2026-07-28") {
		t.Fatalf("version %q missing MCP protocol", stdout.String())
	}
}

func TestUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labsnmp"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("stderr %q missing usage", stderr.String())
	}
}

func TestHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labsnmp", "help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	out := stdout.String()
	for _, s := range []string{"version", "serve", "validate", "canonicalize", "healthcheck", "--snmp-listen"} {
		if !strings.Contains(out, s) {
			t.Fatalf("help missing %s: %q", s, out)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labsnmp", "nope"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/health/ready" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ok.Close()
	var stdout, stderr bytes.Buffer
	code := run([]string{"labsnmp", "healthcheck", "--url", ok.URL + "/v1/health/ready"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ok") {
		t.Fatalf("stdout %q", stdout.String())
	}

	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer down.Close()
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"labsnmp", "healthcheck", "--url", down.URL + "/v1/health/ready"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("not-ready exit %d want 1 stderr=%q", code, stderr.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labsnmp", "not-a-command"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("unknown command exit %d, want 2; stderr=%q", code, stderr.String())
	}
}

func TestMCPStdioRequiresFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labsnmp", "mcp-stdio"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d want 2 stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--config") {
		t.Fatalf("stderr %q", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"labsnmp", "mcp-stdio", "--config", "testdata/config/valid/full.yaml"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d want 2 stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--token-file") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

func TestServeRequiresConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labsnmp", "serve"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d want 2 stderr=%q", code, stderr.String())
	}
}

func TestValidateAndCanonicalize(t *testing.T) {
	t.Chdir(repoRoot(t))
	path := filepath.Join(repoRoot(t), "testdata/config/valid/full.yaml")
	var stdout, stderr bytes.Buffer
	code := run([]string{"labsnmp", "validate", "--config", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("validate exit %d stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ok revision=") {
		t.Fatalf("validate %q", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"labsnmp", "canonicalize", "--config", path, "--format", "json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("canonicalize exit %d stderr=%q", code, stderr.String())
	}
	st, err := config.Load(stdout.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if st.Kind != "LabSNMP" {
		t.Fatalf("kind %q", st.Kind)
	}
}

func TestValidateRequiresConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"labsnmp", "validate"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestValidateInvalidExitsTwo(t *testing.T) {
	t.Chdir(repoRoot(t))
	path := filepath.Join(repoRoot(t), "testdata/config/invalid/unknown-field.yaml")
	var stdout, stderr bytes.Buffer
	code := run([]string{"labsnmp", "validate", "--config", path}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d want 2 stderr=%q", code, stderr.String())
	}
	out := stderr.String()
	if !strings.Contains(out, "spec.foo") || !strings.Contains(out, "unknown_field") {
		t.Fatalf("validate stderr missing field path: %q", out)
	}
}
