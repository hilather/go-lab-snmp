package config

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func TestKnownFieldsUnknownFieldReject(t *testing.T) {
	t.Chdir(repoRoot(t))
	_, err := LoadFile(testdata(t, "invalid", "unknown-field.yaml"))
	de := requireValidation(t, err, violationUnknownField)
	if de.Code != domainerr.CodeUnknownField {
		t.Fatalf("code=%s want unknown_field", de.Code)
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
	if de.Code != domainerr.CodeUnknownField {
		t.Fatalf("code=%s want unknown_field", de.Code)
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
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "community"), []byte("public\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	body := `apiVersion: labsnmp.dev/v1alpha1
kind: LabSNMP
metadata:
  name: x
spec:
  maps:
    - name: system-if
      objects:
        - oid: "10.20.0.3.10.20.0.5.0"
          type: octetString
          value: "x"
  communities:
    - name: public
      communityFile: community
      map: system-if
`
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	st, err := LoadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.Communities[0].CommunityFile != "community" {
		t.Fatalf("communityFile=%q", st.Spec.Communities[0].CommunityFile)
	}
}

func TestCounter64Preserved(t *testing.T) {
	t.Chdir(repoRoot(t))
	st, err := LoadFile(testdata(t, "valid", "full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var got any
	for _, m := range st.Spec.Maps {
		for _, o := range m.Objects {
			if o.Type == model.TypeCounter64 {
				got = o.Value
			}
			if o.Name == "ifOperStatus.1" {
				n, ok := o.Value.(int64)
				if !ok || n != 1 {
					t.Fatalf("integer 1 stored as %T %v", o.Value, o.Value)
				}
			}
		}
	}
	n, ok := got.(uint64)
	if !ok || n != math.MaxUint64 {
		t.Fatalf("counter64 = %T %v want uint64(%d)", got, got, uint64(math.MaxUint64))
	}
	again, err := LoadFile(testdata(t, "valid", "full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rev1, err := Revision(st)
	if err != nil {
		t.Fatal(err)
	}
	rev2, err := Revision(again)
	if err != nil {
		t.Fatal(err)
	}
	if rev1 != rev2 {
		t.Fatalf("revision drifted after counter64 coerce: %s != %s", rev1, rev2)
	}
}

func TestTLS001StillDeferred(t *testing.T) {
	t.Chdir(repoRoot(t))
	for _, name := range []string{"dtls-enabled.yaml", "tcp-enabled.yaml"} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadFile(testdata(t, "invalid", name))
			de := requireValidation(t, err, violationTLSUnsupported)
			if de.Code != domainerr.CodeTLSUnsupported {
				t.Fatalf("code=%s want tls_unsupported", de.Code)
			}
		})
	}
}
