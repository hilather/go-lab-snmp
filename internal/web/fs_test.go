package web

import (
	"io/fs"
	"strings"
	"testing"
)

func TestCommittedDistPlaceholder(t *testing.T) {
	raw, err := fs.ReadFile(Files(), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		t.Fatal("internal/web/dist/index.html is empty")
	}
	body := string(raw)
	if !strings.Contains(body, "LabSNMP") {
		t.Fatalf("committed dist missing LabSNMP: %s", body)
	}
}

func TestUIEnabledOff(t *testing.T) {
	if UIEnabled {
		t.Fatal("UIEnabled must be false")
	}
}
