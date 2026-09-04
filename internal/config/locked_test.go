package config

import (
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
)

func TestKnownFieldsUnknownFieldReject(t *testing.T) {
	t.Chdir(repoRoot(t))
	_, err := LoadFile(testdata(t, "invalid", "unknown-field.yaml"))
	de := requireValidation(t, err, violationUnknownField)
	if de.Code != domainerr.CodeUnknownField && de.Code != domainerr.CodeValidationFailed {
		t.Fatalf("code=%s", de.Code)
	}
}

func TestReservedKeyReject(t *testing.T) {
	t.Chdir(repoRoot(t))
	_, err := LoadFile(testdata(t, "invalid", "reserved-key.yaml"))
	de := requireValidation(t, err, violationReservedKey)
	if de.Code != domainerr.CodeReservedKey {
		t.Fatalf("code=%s want reserved_key", de.Code)
	}
}

func TestUSMAlgUnsupported(t *testing.T) {
	t.Chdir(repoRoot(t))
	for _, name := range []string{"usm-sha384.yaml", "usm-aes256.yaml"} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFile(testdata(t, "invalid", name))
			de := requireValidation(t, err, violationUSMAlgUnsupported)
			if de.Code != domainerr.CodeUSMAlgUnsupported {
				t.Fatalf("code=%s want usm_alg_unsupported", de.Code)
			}
		})
	}
}

func TestManagementAuthUnknown(t *testing.T) {
	t.Chdir(repoRoot(t))
	_, err := LoadFile(testdata(t, "invalid", "management-auth.yaml"))
	de := requireValidation(t, err, violationUnknownField)
	if de.Code != domainerr.CodeUnknownField && de.Code != domainerr.CodeValidationFailed {
		t.Fatalf("code=%s", de.Code)
	}
	found := false
	for _, v := range de.FieldViolations {
		if v.Path == "spec.management.auth" || v.Path == "management.auth" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("want spec.management.auth in %+v", de.FieldViolations)
	}
}

func TestTokenShortOrMissingFile(t *testing.T) {
	t.Chdir(repoRoot(t))
	_, err := LoadFile(testdata(t, "invalid", "token-short.yaml"))
	_ = requireValidation(t, err, violationInvalidValue)
	_, err = LoadFile(testdata(t, "invalid", "token-missing-file.yaml"))
	_ = requireValidation(t, err, violationInvalidValue)
}

func TestLoadFileUsesConfigDir(t *testing.T) {
	root := repoRoot(t)
	t.Chdir(t.TempDir())
	_, err := LoadFile(filepath.Join(root, "testdata", "config", "valid", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
}
