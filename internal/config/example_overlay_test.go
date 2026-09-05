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
// Overlay secret paths are /run/secrets in the integrator; this test rewrites
// them onto testdata/secrets and LoadFiles so Validate (duplicate OIDs, USM,
// token length) cannot skip.
func TestLabOverlayExample(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "examples", "labsnmp.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if strings.Contains(text, "LABSNMP_MGMT_PORT") {
		t.Fatal("overlay must not mention rejected alias LABSNMP_MGMT_PORT")
	}
	for _, p := range []string{
		"/run/secrets/labsnmp-token",
		"/run/secrets/snmp-public",
		"/run/secrets/snmp-private",
		"/run/secrets/snmp-alice-auth",
		"/run/secrets/snmp-alice-priv",
	} {
		if !strings.Contains(text, p) {
			t.Fatalf("overlay missing %s", p)
		}
	}

	dir := t.TempDir()
	copies := map[string]string{
		"labsnmp-token":   "token-admin",
		"snmp-public":     "snmp-public",
		"snmp-private":    "snmp-private",
		"snmp-alice-auth": "snmp-alice-auth",
		"snmp-alice-priv": "snmp-alice-priv",
	}
	for dest, src := range copies {
		in, err := os.ReadFile(filepath.Join(root, "testdata", "secrets", src))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, dest), in, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rewritten := strings.ReplaceAll(text, "/run/secrets/", filepath.ToSlash(dir)+"/")
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte(rewritten), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := LoadFile(cfg)
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
		if tok.ID == "admin" && strings.HasSuffix(tok.SecretFile, "labsnmp-token") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("missing admin token labsnmp-token")
	}

	maps := map[string]model.MapSpec{}
	for _, m := range st.Spec.Maps {
		maps[m.Name] = m
	}
	if _, ok := maps["public-if"]; !ok {
		t.Fatal("missing map public-if")
	}
	if _, ok := maps["private-if"]; !ok {
		t.Fatal("missing map private-if")
	}
	wantIfDescr1 := strings.Join([]string{"1", "3", "6", "1", "2", "1", "2", "2", "1", "2", "1"}, ".")
	wantIfDescr2 := strings.Join([]string{"1", "3", "6", "1", "2", "1", "2", "2", "1", "2", "2"}, ".")
	wantIfIndex1 := strings.Join([]string{"1", "3", "6", "1", "2", "1", "2", "2", "1", "1", "1"}, ".")
	got := map[string]string{}
	for _, o := range maps["public-if"].Objects {
		got[o.Name] = o.OID
	}
	if got["ifDescr.1"] != wantIfDescr1 {
		t.Fatalf("ifDescr.1 oid=%q want %q", got["ifDescr.1"], wantIfDescr1)
	}
	if got["ifDescr.2"] != wantIfDescr2 {
		t.Fatalf("ifDescr.2 oid=%q want %q", got["ifDescr.2"], wantIfDescr2)
	}
	if got["ifIndex.1"] != wantIfIndex1 {
		t.Fatalf("ifIndex.1 oid=%q want %q", got["ifIndex.1"], wantIfIndex1)
	}
	if got["ifDescr.1"] == got["ifIndex.1"] {
		t.Fatal("ifDescr.1 must not reuse ifIndex.1")
	}

	comms := map[string]model.CommunitySpec{}
	for _, c := range st.Spec.Communities {
		comms[c.Name] = c
	}
	pub, ok := comms["public"]
	if !ok || !strings.HasSuffix(pub.CommunityFile, "snmp-public") || pub.Map != "public-if" {
		t.Fatalf("community public = %+v", pub)
	}
	priv, ok := comms["private"]
	if !ok || !strings.HasSuffix(priv.CommunityFile, "snmp-private") || priv.Map != "private-if" {
		t.Fatalf("community private = %+v", priv)
	}

	if len(st.Spec.Users) != 1 || st.Spec.Users[0].Name != "alice" {
		t.Fatalf("users=%+v want alice", st.Spec.Users)
	}
	alice := st.Spec.Users[0]
	if alice.Level != model.LevelAuthPriv || alice.Map != "private-if" {
		t.Fatalf("alice level=%q map=%q", alice.Level, alice.Map)
	}
	if alice.Auth == nil || alice.Auth.Protocol != model.AuthSHA256 || !strings.HasSuffix(alice.Auth.SecretFile, "snmp-alice-auth") {
		t.Fatalf("alice auth=%+v", alice.Auth)
	}
	if alice.Priv == nil || alice.Priv.Protocol != model.PrivAES128 || !strings.HasSuffix(alice.Priv.SecretFile, "snmp-alice-priv") {
		t.Fatalf("alice priv=%+v", alice.Priv)
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
