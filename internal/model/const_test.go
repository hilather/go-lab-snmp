package model

import "testing"

func TestAPIConstants(t *testing.T) {
	if APIVersionV1Alpha1 != "labsnmp.dev/v1alpha1" {
		t.Fatalf("apiVersion = %q", APIVersionV1Alpha1)
	}
	if KindLabSNMP != "LabSNMP" {
		t.Fatalf("kind = %q", KindLabSNMP)
	}
	if RevisionPrefix != "sha256:" {
		t.Fatalf("prefix = %q", RevisionPrefix)
	}
	if !KnownOp(OpReplaceMaps) || KnownOp("jsonPatch") {
		t.Fatal("KnownOp")
	}
	if !KnownRole(RoleAdministrator) || !KnownRole(RoleReader) || KnownRole("operator") || KnownRole("viewer") {
		t.Fatal("KnownRole")
	}
	if !KnownObjectType(TypeOctetString) || KnownObjectType("bits") {
		t.Fatal("KnownObjectType")
	}
	admin := ScopesForRole(RoleAdministrator)
	if len(admin) != 4 {
		t.Fatalf("administrator scopes = %v", admin)
	}
	reader := ScopesForRole(RoleReader)
	if len(reader) != 1 || reader[0] != ScopeSNMPRead {
		t.Fatalf("reader scopes = %v", reader)
	}
}
