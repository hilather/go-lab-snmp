package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/config"
)

func TestDockerfileContract(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, "FROM golang:1.26-alpine AS build") {
		t.Fatal("Dockerfile must use golang:1.26-alpine, not a hard 1.26.6 pin")
	}
	if strings.Contains(s, "1.26.6") {
		t.Fatal("Dockerfile must not pin golang 1.26.6")
	}
	if !strings.Contains(s, "FROM scratch") {
		t.Fatal("Dockerfile must produce a scratch image")
	}
	if !strings.Contains(s, "USER 65532:65532") {
		t.Fatal("Dockerfile must set USER 65532:65532")
	}
	if !strings.Contains(s, "CGO_ENABLED=0") {
		t.Fatal("Dockerfile must build with CGO_ENABLED=0")
	}
	if strings.Contains(s, "FROM node") || strings.Contains(s, "npm ") {
		t.Fatal("Dockerfile must not have a Node stage")
	}
	if !strings.Contains(s, `CMD ["serve", "--config=/etc/labsnmp/config.yaml", "--management-listen=:8088"]`) {
		t.Fatal("image CMD must bind management :8088")
	}
	if !strings.Contains(s, "/v1/health/ready") {
		t.Fatal("HEALTHCHECK must hit /v1/health/ready")
	}
	if !strings.Contains(s, "EXPOSE 161/udp 162/udp 8088/tcp") {
		t.Fatal("Dockerfile must EXPOSE 161/udp 162/udp 8088/tcp")
	}
}

func TestComposeSmokeContract(t *testing.T) {
	t.Parallel()
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "examples/compose.smoke.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, want := range []string{
		"labsnmp:",
		"build:",
		"context: ..",
		"--snmp-listen=:1161",
		"--trap-listen=:1162",
		"--management-listen=:8088",
		"cap_drop:",
		"- ALL",
		`user: "65532:65532"`,
		"/v1/health/ready",
		"start_period: 3s",
		"127.0.0.1:1161:1161/udp",
		"127.0.0.1:1162:1162/udp",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("compose.smoke.yaml missing %q", want)
		}
	}
	if strings.Contains(s, "cap_add:") {
		t.Fatal("compose.smoke.yaml must cap_drop ALL without cap_add")
	}
	if strings.Contains(s, "10161") || strings.Contains(s, "10162") {
		t.Fatal("compose.smoke.yaml uses :1161/:1162, not residual 10161/10162")
	}
}

func TestContainerConfigLoads(t *testing.T) {
	t.Chdir(repoRoot(t))
	st, err := config.LoadFile("testdata/container/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if st.Metadata.Name != "container-smoke" {
		t.Fatalf("name %q", st.Metadata.Name)
	}
	if st.Spec.UI.Enabled {
		t.Fatal("container smoke ui.enabled must be false")
	}
	if len(st.Spec.Auth.Tokens) == 0 {
		t.Fatal("container smoke needs a bearer token")
	}
}
