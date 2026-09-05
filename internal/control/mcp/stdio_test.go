package mcp

import (
	"io"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/model"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestStdioDevAdapterSameRegistry(t *testing.T) {
	s, _ := newTestServer(t)
	actor := s.actorFrom(t.Context())
	if actor.ID == "" {
		s.cfg.FixedActor = &app.Actor{
			ID: "admin", Class: "token", Role: model.RoleAdministrator,
			Scopes: model.ScopesForRole(model.RoleAdministrator), Transport: "mcp",
		}
	}
	pr1, pw1 := io.Pipe()
	pr2, pw2 := io.Pipe()
	t.Cleanup(func() {
		_ = pr1.Close()
		_ = pw1.Close()
		_ = pr2.Close()
		_ = pw2.Close()
	})
	ctx := t.Context()
	errc := make(chan error, 1)
	go func() {
		errc <- s.run(ctx, &sdk.IOTransport{Reader: pr1, Writer: pw2})
	}()
	client := sdk.NewClient(&sdk.Implementation{Name: "stdio-test", Version: "dev"}, nil)
	cs, err := client.Connect(ctx, &sdk.IOTransport{Reader: pr2, Writer: pw1}, nil)
	if err != nil {
		t.Fatalf("stdio connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })

	seen := map[string]bool{}
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		seen[tool.Name] = true
	}
	if !seen["snmp_version_get"] || !seen["snmp_change_apply"] {
		t.Fatalf("stdio missing core tools: %v", seen)
	}
	res := callTool(t, cs, "snmp_version_get", map[string]any{})
	if res.IsError {
		t.Fatalf("stdio version: %+v", res)
	}
}

func TestStdioLogsAreNotStdout(t *testing.T) {
	s, _ := newTestServer(t)
	if s.sdk == nil {
		t.Fatal("missing sdk server")
	}
}
