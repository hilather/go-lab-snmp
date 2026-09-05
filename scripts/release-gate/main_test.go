package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateNotes(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok.md")
	body := "# LabSNMP 1.0.0\n\n## Highlights\n\nx\n\n## Added\n\nx\n\n## Residual\n\nx\n\n## Deployment and operations\n\nx\n\n## CI and release evidence\n\nx\n"
	if err := os.WriteFile(ok, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateNotes(ok); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.md")
	if err := os.WriteFile(bad, []byte("# x\nTODO\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateNotes(bad); err == nil {
		t.Fatal("expected missing headings")
	}
}

func TestValidateNotesRejectsPlaceholder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notes.md")
	body := "# x\n\n## Highlights\n\n## Added\n\n## Residual\n\n## Deployment and operations\n\n## CI and release evidence\n\nTBD\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateNotes(path); err == nil {
		t.Fatal("expected TBD reject")
	}
}

func TestValidateRepoV1Notes(t *testing.T) {
	root := repoRootForTest(t)
	path := filepath.Join(root, "docs", "releases", "v1.0.0.md")
	if err := validateNotes(path); err != nil {
		t.Fatal(err)
	}
}

func repoRootForTest(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
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
