package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/model"
)

// TestLabOverlayExample loads examples/labsnmp.yaml (the mcp-integration-lab
// bootstrap BOM) and checks knobs the lab PR must not regress.
// Secret files live at /run/secrets in the integrator, so this test Decodes
// (KnownFields) rather than LoadFile.
func TestLabOverlayExample(t *testing.T) {
	path := filepath.Join(repoRoot(t), "examples", "labsnmp.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Spec.Management.MCP.AllowLegacyClients {
		t.Fatal("lab overlay must set allowLegacyClients: true")
	}
	if st.Spec.Auth.Mode != model.MgmtAuthBearer {
		t.Fatalf("auth.mode=%q want bearer", st.Spec.Auth.Mode)
	}
	if st.Spec.Listeners.Agent.Address != ":161" || st.Spec.Listeners.Traps.Address != ":162" || st.Spec.Listeners.Management.Address != ":8088" {
		t.Fatalf("listeners agent=%q traps=%q mgmt=%q", st.Spec.Listeners.Agent.Address, st.Spec.Listeners.Traps.Address, st.Spec.Listeners.Management.Address)
	}
	if !st.Spec.Listeners.Agent.Enabled || !st.Spec.Listeners.Traps.Enabled {
		t.Fatal("agent and trap listeners must stay enabled")
	}
	if st.Spec.Listeners.DTLS.Enabled || st.Spec.Listeners.TCP.Enabled {
		t.Fatal("dtls/tcp enabled must stay false in 1.0")
	}
	if !st.Spec.UI.Enabled {
		t.Fatal("ui.enabled must stay true (operator SPA)")
	}
	wantCIDRs := []string{"10.99.42.0/24", "127.0.0.0/8", "::1/128"}
	if !slices.Equal(st.Spec.Admission.AllowClientCidrs, wantCIDRs) {
		t.Fatalf("allowClientCidrs=%v want %v", st.Spec.Admission.AllowClientCidrs, wantCIDRs)
	}
	found := false
	for _, tok := range st.Spec.Auth.Tokens {
		if tok.ID == "admin" && tok.SecretFile == "/run/secrets/labsnmp-token" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("missing admin token at /run/secrets/labsnmp-token")
	}

	maps := map[string]bool{}
	for _, m := range st.Spec.Maps {
		maps[m.Name] = true
	}
	if !maps["public-if"] || !maps["private-if"] {
		t.Fatalf("maps=%v want public-if and private-if", maps)
	}

	comms := map[string]model.CommunitySpec{}
	for _, c := range st.Spec.Communities {
		comms[c.Name] = c
	}
	pub, ok := comms["public"]
	if !ok || pub.CommunityFile != "/run/secrets/snmp-public" || pub.Map != "public-if" {
		t.Fatalf("community public = %+v", pub)
	}
	priv, ok := comms["private"]
	if !ok || priv.CommunityFile != "/run/secrets/snmp-private" || priv.Map != "private-if" {
		t.Fatalf("community private = %+v", priv)
	}

	if len(st.Spec.Users) != 1 || st.Spec.Users[0].Name != "alice" {
		t.Fatalf("users=%+v want alice", st.Spec.Users)
	}
	alice := st.Spec.Users[0]
	if alice.Level != model.LevelAuthPriv || alice.Map != "private-if" {
		t.Fatalf("alice level=%q map=%q", alice.Level, alice.Map)
	}
	if alice.Auth == nil || alice.Auth.Protocol != model.AuthSHA256 || alice.Auth.SecretFile != "/run/secrets/snmp-alice-auth" {
		t.Fatalf("alice auth=%+v", alice.Auth)
	}
	if alice.Priv == nil || alice.Priv.Protocol != model.PrivAES128 || alice.Priv.SecretFile != "/run/secrets/snmp-alice-priv" {
		t.Fatalf("alice priv=%+v", alice.Priv)
	}

	text := string(b)
	if strings.Contains(text, "LABSNMP_MGMT_PORT") {
		t.Fatal("overlay must not mention rejected alias LABSNMP_MGMT_PORT")
	}
}

func TestLabMCPJungleExamples(t *testing.T) {
	root := filepath.Join(repoRoot(t), "examples", "mcpjungle")
	raw, err := os.ReadFile(filepath.Join(root, "servers", "labsnmp.json"))
	if err != nil {
		t.Fatal(err)
	}
	var server struct {
		Name        string `json:"name"`
		Transport   string `json:"transport"`
		URL         string `json:"url"`
		BearerToken string `json:"bearer_token"`
	}
	if err := json.Unmarshal(raw, &server); err != nil {
		t.Fatal(err)
	}
	if server.Name != "labsnmp" {
		t.Fatalf("name=%q (filename must match name)", server.Name)
	}
	if server.Transport != "streamable_http" {
		t.Fatalf("transport=%q", server.Transport)
	}
	if server.URL != "http://labsnmp:8088/mcp" {
		t.Fatalf("url=%q", server.URL)
	}
	if server.BearerToken != "${LABSNMP_TOKEN}" {
		t.Fatalf("bearer_token=%q", server.BearerToken)
	}

	grow, err := os.ReadFile(filepath.Join(root, "groups", "integration.json"))
	if err != nil {
		t.Fatal(err)
	}
	var group struct {
		Name            string   `json:"name"`
		IncludedServers []string `json:"included_servers"`
	}
	if err := json.Unmarshal(grow, &group); err != nil {
		t.Fatal(err)
	}
	if group.Name != "integration" {
		t.Fatalf("group name=%q", group.Name)
	}
	if !slices.Contains(group.IncludedServers, "labsnmp") {
		t.Fatalf("included_servers=%v must append labsnmp", group.IncludedServers)
	}
	for _, keep := range []string{"labdns", "labldap", "labtacacs", "labinfo", "labmail", "labmitm", "labntp"} {
		if !slices.Contains(group.IncludedServers, keep) {
			t.Fatalf("included_servers=%v dropped %q (append labsnmp; do not replace)", group.IncludedServers, keep)
		}
	}
}

func TestLabinfoSnippetKeepsCatalogID(t *testing.T) {
	path := filepath.Join(repoRoot(t), "examples", "labinfo", "services-labsnmp.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "id: labsnmp") {
		t.Fatal("catalog id must be labsnmp")
	}
	if strings.Contains(text, "id: snmpd") {
		t.Fatal("do not reuse a snmpd catalog id")
	}
	if !strings.Contains(text, "/v1") || !strings.Contains(text, "/mcp") {
		t.Fatal("snippet must add native /v1 and MCP URLs")
	}
	if !strings.Contains(text, "urls:") || !strings.Contains(text, "connection:") {
		t.Fatal("labinfo must include urls + connection")
	}
	if !strings.Contains(text, "LABSNMP_REST_PORT") {
		t.Fatal("snippet must use LABSNMP_REST_PORT")
	}
	if strings.Contains(text, "LABSNMP_MGMT_PORT") {
		t.Fatal("LABSNMP_MGMT_PORT is a rejected alias")
	}
	if !strings.Contains(text, "LABSNMP_AGENT_PORT") || !strings.Contains(text, "LABSNMP_TRAP_PORT") {
		t.Fatal("snippet must name residual agent/trap ports")
	}
	if !strings.Contains(text, "public-if") || !strings.Contains(text, "private-if") {
		t.Fatal("snippet must name maps public-if / private-if")
	}
	if !strings.Contains(text, "alice") {
		t.Fatal("snippet must name user alice")
	}
	if !strings.Contains(text, "labsnmp-token") {
		t.Fatal("snippet must add bearer credential file")
	}
}
