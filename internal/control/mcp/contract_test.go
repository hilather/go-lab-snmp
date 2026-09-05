package mcp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/capabilities"
	"github.com/hilather/go-lab-snmp/internal/store"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestToolsRegisteredFromRegistry(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	seen := map[string]bool{}
	for tool, err := range cs.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		seen[tool.Name] = true
		if tool.InputSchema == nil {
			t.Errorf("%s missing input schema", tool.Name)
		}
	}
	want := capabilities.Tools()
	if len(seen) != len(want) {
		t.Errorf("live tools=%d registry=%d", len(seen), len(want))
	}
	for _, name := range want {
		if !seen[name] {
			t.Errorf("missing tool %s", name)
		}
	}
	for name := range seen {
		found := false
		for _, w := range want {
			if w == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("extra live tool %s", name)
		}
	}
	if seen["health.live"] || seen["snmp_health_live"] {
		t.Fatal("health live must not be a tool")
	}
}

func TestResourcesRegisteredFromRegistry(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	seen := map[string]bool{}
	for r, err := range cs.Resources(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		seen[r.URI] = true
	}
	for tmpl, err := range cs.ResourceTemplates(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		seen[tmpl.URITemplate] = true
	}
	want := capabilities.Resources()
	if len(seen) != len(want) {
		t.Errorf("live resources=%d registry=%d seen=%v want=%v", len(seen), len(want), seen, want)
	}
	for _, uri := range want {
		if !seen[uri] {
			t.Errorf("missing resource %s", uri)
		}
	}
	for uri := range seen {
		found := false
		for _, w := range want {
			if w == uri {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("extra live resource %s", uri)
		}
	}
}

func TestContractReads(t *testing.T) {
	s, svc := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)

	ver := structuredMap(t, callTool(t, cs, "snmp_version_get", map[string]any{}))
	if ver["protocols"] == nil {
		t.Fatalf("version=%v", ver)
	}
	caps := structuredMap(t, callTool(t, cs, "snmp_capabilities_get", map[string]any{}))
	if caps["capabilities"] == nil {
		t.Fatalf("capabilities=%v", caps)
	}
	st := structuredMap(t, callTool(t, cs, "snmp_status_get", map[string]any{}))
	if st["revisions"] == nil {
		t.Fatalf("status=%v", st)
	}
	schema := callTool(t, cs, "snmp_schema_get", map[string]any{})
	raw, _ := json.Marshal(schema.StructuredContent)
	if !strings.Contains(string(raw), "labsnmp.dev/v1alpha1") {
		t.Fatalf("schema missing api version: %s", raw)
	}

	state := structuredMap(t, callTool(t, cs, "snmp_state_get", map[string]any{}))
	if state["runtimeRevision"] == "" {
		t.Fatalf("state=%v", state)
	}

	features := structuredMap(t, callTool(t, cs, "snmp_features_list", map[string]any{}))
	items, _ := features["items"].([]any)
	if len(items) != len(capabilities.Features()) {
		t.Fatalf("features=%v", features)
	}

	maps := structuredMap(t, callTool(t, cs, "snmp_maps_list", map[string]any{}))
	if maps["items"] == nil {
		t.Fatalf("maps=%v", maps)
	}
	got := structuredMap(t, callTool(t, cs, "snmp_map_get", map[string]any{"name": "public-if"}))
	if got["name"] != "public-if" {
		t.Fatalf("map get=%v", got)
	}
	q := structuredMap(t, callTool(t, cs, "snmp_map_query", map[string]any{
		"name": "public-if", "pdu": "get", "oids": []string{"1.3.6.1.2.1.1.1.0"},
	}))
	bindings, _ := q["bindings"].([]any)
	if len(bindings) != 1 {
		t.Fatalf("query=%v", q)
	}

	preview := structuredMap(t, callTool(t, cs, "snmp_preview_get", map[string]any{
		"community": "public", "oid": "1.3.6.1.2.1.1.1.0",
	}))
	if preview["value"] != "LabSNMP public-if" {
		t.Fatalf("preview=%v", preview)
	}

	users := structuredMap(t, callTool(t, cs, "snmp_users_list", map[string]any{}))
	rawUsers, _ := json.Marshal(users)
	if strings.Contains(string(rawUsers), "alice-auth-pass") {
		t.Fatalf("USM secret leaked: %s", rawUsers)
	}

	id, err := svc.Traps().Insert(store.TrapRecord{
		Version:         "v2c",
		PDUType:         "trapv2",
		Community:       "public",
		NotificationOID: "1.3.6.1.6.3.1.1.5.1",
		ReceivedAt:      time.Now().UTC(),
		Raw:             []byte{0x30, 0x00},
	})
	if err != nil {
		t.Fatal(err)
	}
	waited := structuredMap(t, callTool(t, cs, "snmp_traps_wait", map[string]any{"timeout": "2s", "community": "public"}))
	if waited["id"] != id {
		t.Fatalf("wait=%v want %s", waited, id)
	}

	stateRes, err := cs.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: "labsnmp://state"})
	if err != nil {
		t.Fatal(err)
	}
	if len(stateRes.Contents) == 0 || !strings.Contains(stateRes.Contents[0].Text, "runtimeRevision") {
		t.Fatalf("resource state=%+v", stateRes)
	}
	mapRes, err := cs.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: "labsnmp://maps/public-if"})
	if err != nil {
		t.Fatal(err)
	}
	if len(mapRes.Contents) == 0 || !strings.Contains(mapRes.Contents[0].Text, "public-if") {
		t.Fatalf("resource map=%+v", mapRes)
	}
	trapRes, err := cs.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: "labsnmp://traps/" + id})
	if err != nil {
		t.Fatal(err)
	}
	if len(trapRes.Contents) == 0 || !strings.Contains(trapRes.Contents[0].Text, `"id"`) {
		t.Fatalf("resource trap=%+v", trapRes)
	}
}

func TestContractOIDSet(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	set := structuredMap(t, callTool(t, cs, "snmp_oid_set", map[string]any{
		"name": "public-if", "oid": "1.3.6.1.2.1.2.2.1.8.1", "value": 2,
	}))
	if set["overlay"] != true {
		t.Fatalf("set=%v", set)
	}
	got := structuredMap(t, callTool(t, cs, "snmp_oid_get", map[string]any{
		"name": "public-if", "oid": "1.3.6.1.2.1.2.2.1.8.1",
	}))
	if got["overlay"] != true {
		t.Fatalf("get=%v", got)
	}
}

func TestContractReset(t *testing.T) {
	s, _ := newTestServer(t)
	ts := startHTTP(t, s)
	cs := connectClient(t, ts)
	res := structuredMap(t, callTool(t, cs, "snmp_state_reset", map[string]any{"reason": "mcp"}))
	if res["applied"] != true {
		t.Fatalf("reset=%v", res)
	}
}
