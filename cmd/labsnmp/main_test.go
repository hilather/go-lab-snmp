package main

import (
	"bytes"
	"strings"
	"testing"
)

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

func TestUnimplementedCommands(t *testing.T) {
	for _, cmd := range []string{"validate", "canonicalize", "serve", "healthcheck", "mcp-stdio"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"labsnmp", cmd}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("%s exit %d, want 1; stderr=%q", cmd, code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "not implemented") {
			t.Fatalf("%s stderr %q", cmd, stderr.String())
		}
	}
}
