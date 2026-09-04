package main

import "testing"

func TestCheckChangelogRequiresEntry(t *testing.T) {
	err := checkChangelog([]string{"internal/snmpagent/server.go"})
	if err == nil {
		t.Fatal("expected missing changelog")
	}
	err = checkChangelog([]string{"internal/snmpagent/server.go", "CHANGELOG.md"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCheckChangelogIgnoresTestsAndUnobservable(t *testing.T) {
	if err := checkChangelog([]string{"internal/mibtree/tree_test.go", "docs/01-architecture.md"}); err != nil {
		t.Fatal(err)
	}
}

func TestObservableRel(t *testing.T) {
	if !observableRel("docs/02-snmp-semantics.md") {
		t.Fatal("snmp-semantics should be observable")
	}
	if !observableRel("cmd/labsnmp/main.go") {
		t.Fatal("cmd should be observable")
	}
	if observableRel("internal/mibtree/tree_test.go") {
		t.Fatal("tests are not observable")
	}
	if observableRel("CHANGELOG.md") {
		t.Fatal("changelog itself is not an observable trigger")
	}
}

func TestCheckMissingBaseIsEmptyDiff(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(root, "refs/does-not-exist"); err != nil {
		t.Fatal(err)
	}
	if err := Check(root, ""); err != nil {
		t.Fatal(err)
	}
}
