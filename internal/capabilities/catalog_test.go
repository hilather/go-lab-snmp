package capabilities

import (
	"strings"
	"testing"
)

func TestCatalogRowCountAndSNMPPrefix(t *testing.T) {
	if err := ValidateCatalog(); err != nil {
		t.Fatal(err)
	}
	if len(All()) != TableRowCount {
		t.Fatalf("rows %d", len(All()))
	}
	for _, name := range Tools() {
		if !strings.HasPrefix(name, "snmp_") {
			t.Errorf("tool %s must start with snmp_", name)
		}
		if strings.HasPrefix(name, "labsnmp_") {
			t.Errorf("tool %s uses rejected labsnmp_ prefix", name)
		}
	}
	for _, r := range Resources() {
		if !strings.HasPrefix(r, "labsnmp://") {
			t.Errorf("resource %s must use labsnmp://", r)
		}
	}
}

func TestFeaturesFrozen(t *testing.T) {
	ids := FeatureIDs()
	want := []string{
		"maps", "communities", "users", "trapStorePolicy", "admission", "agentCaps", "observability",
		"listeners.agent.address", "listeners.traps.address", "listeners.management.address", "engine", "auth",
	}
	if len(ids) != len(want) {
		t.Fatalf("%v", ids)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("id[%d]=%s want %s", i, ids[i], want[i])
		}
	}
	for _, f := range Features() {
		if f.Apply != FeatureApplyLive && f.Apply != FeatureApplyResetOnly {
			t.Errorf("%s apply=%s", f.ID, f.Apply)
		}
		if f.ID == "ui.enabled" || f.ID == "dtls" || f.ID == "tcp" {
			t.Errorf("invented feature id %s", f.ID)
		}
	}
}

func TestRESTOnlyHealthAndNoInventedIDs(t *testing.T) {
	if _, ok := Lookup(HealthLive); !ok {
		t.Fatal("health.live")
	}
	if _, ok := Lookup(HealthReady); !ok {
		t.Fatal("health.ready")
	}
	if _, ok := LookupREST("GET", "/v1/health/live"); !ok {
		t.Fatal("live REST")
	}
	if _, ok := Lookup("filters.list"); ok {
		t.Fatal("do not copy LabNTP capability ids")
	}
}
