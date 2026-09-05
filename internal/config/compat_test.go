package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

var expectedInvalid = map[string]string{
	"unknown-field.yaml":                violationUnknownField,
	"unknown-kebab.yaml":                violationUnknownField,
	"reserved-key.yaml":                 violationReservedKey,
	"reserved-snmpd.yaml":               violationReservedKey,
	"usm-sha384.yaml":                   violationUSMAlgUnsupported,
	"usm-aes256.yaml":                   violationUSMAlgUnsupported,
	"management-auth.yaml":              violationUnknownField,
	"token-short.yaml":                  violationInvalidValue,
	"token-missing-file.yaml":           violationInvalidValue,
	"dtls-enabled-no-cert.yaml":         violationRequired,
	"dtls-bad-pem.yaml":                 violationInvalidValue,
	"dtls-bad-client-ca.yaml":           violationInvalidValue,
	"dtls-udp-collision.yaml":           violationInvalidValue,
	"tcp-only-no-identity.yaml":         violationRequired,
	"tcp-enabled-no-address.yaml":       violationRequired,
	"no-agent-plane.yaml":               violationRequired,
	"listeners-tls.yaml":                violationUnknownField,
	"community-inline.yaml":             violationUnknownField,
	"community-secretFile.yaml":         violationUnknownField,
	"missing-communityFile.yaml":        violationRequired,
	"duplicate-community-wire.yaml":     violationDuplicateID,
	"duplicate-user.yaml":               violationDuplicateID,
	"unknown-map.yaml":                  violationInvalidValue,
	"valueFrom-processUptime.yaml":      violationInvalidValue,
	"valueFrom-uptime-octetString.yaml": violationInvalidValue,
	"valueFrom-uptime-write.yaml":       violationInvalidValue,
	"multi-doc.yaml":                    violationInvalidValue,
	"token-scopes.yaml":                 violationUnknownField,
	"usm-short.yaml":                    violationInvalidValue,
	"missing-identity.yaml":             violationRequired,
}

func TestConfigCompat(t *testing.T) {
	t.Chdir(repoRoot(t))
	validDir := testdata(t, "valid")
	ents, err := os.ReadDir(validDir)
	if err != nil {
		t.Fatal(err)
	}
	var validCount int
	revs := map[string]model.Revision{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		validCount++
		name := e.Name()
		t.Run("valid/"+name, func(t *testing.T) {
			st, _, err := LoadFileWithWarnings(filepath.Join(validDir, name))
			if err != nil {
				t.Fatal(err)
			}
			if st.APIVersion != model.APIVersionV1Alpha1 || st.Kind != model.KindLabSNMP {
				t.Fatalf("api=%q kind=%q", st.APIVersion, st.Kind)
			}
			rev, err := Revision(st)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(string(rev), model.RevisionPrefix) {
				t.Fatalf("revision %q", rev)
			}
			revs[name] = rev
			raw, err := CanonicalYAML(st)
			if err != nil {
				t.Fatal(err)
			}
			again, err := Load(raw)
			if err != nil {
				t.Fatal(err)
			}
			rev2, err := Revision(again)
			if err != nil {
				t.Fatal(err)
			}
			if rev != rev2 {
				t.Fatalf("round-trip revision %s != %s", rev, rev2)
			}
			rev3, err := Revision(st)
			if err != nil {
				t.Fatal(err)
			}
			if rev != rev3 {
				t.Fatalf("revision not stable: %s != %s", rev, rev3)
			}
		})
	}
	if validCount < 3 {
		t.Fatalf("expected defaults, full, and split-horizon, got %d", validCount)
	}

	invalidDir := testdata(t, "invalid")
	ients, err := os.ReadDir(invalidDir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range ients {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := e.Name()
		want, ok := expectedInvalid[name]
		if !ok {
			t.Errorf("invalid/%s has no expectedInvalid entry", name)
			continue
		}
		seen[name] = true
		t.Run("invalid/"+name, func(t *testing.T) {
			_, err := LoadFile(filepath.Join(invalidDir, name))
			if err == nil {
				t.Fatal("expected error")
			}
			de, ok := domainerr.As(err)
			if !ok {
				t.Fatalf("error is %T %v", err, err)
			}
			found := string(de.Code) == want
			for _, v := range de.FieldViolations {
				if v.Code == want {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("want code %q in domain=%s violations=%+v (err=%v)", want, de.Code, de.FieldViolations, err)
			}
		})
	}
	for name := range expectedInvalid {
		if !seen[name] {
			t.Errorf("expectedInvalid %s missing on disk", name)
		}
	}
}

func TestValidateNil(t *testing.T) {
	_ = requireValidation(t, Validate(nil), violationRequired)
}

func TestSchemaFilePresent(t *testing.T) {
	t.Chdir(repoRoot(t))
	b, err := SchemaBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "labsnmp.dev/v1alpha1") {
		t.Fatal("schema missing api version")
	}
	if !strings.Contains(string(b), "communityFile") {
		t.Fatal("schema missing communityFile")
	}
	if strings.Contains(string(b), `"scopes"`) {
		t.Fatal("schema must not include tokens[].scopes")
	}
	if strings.Contains(string(b), "processUptime") {
		t.Fatal("schema must not include processUptime")
	}
	if !strings.Contains(string(b), `"tcpListener"`) || !strings.Contains(string(b), `"dtlsListener"`) {
		t.Fatal("schema missing tcpListener/dtlsListener")
	}
	if !strings.Contains(string(b), "trapsAddress") || !strings.Contains(string(b), "certFile") {
		t.Fatal("schema missing tcp/dtls file-ref fields")
	}
	if strings.Contains(string(b), `"toggle"`) {
		t.Fatal("schema must not keep $defs/toggle")
	}
	if strings.Contains(string(b), `"tls":`) {
		t.Fatal("schema must not include spec.listeners.tls")
	}
}

func TestRevisionExcludesSecretBytes(t *testing.T) {
	t.Chdir(repoRoot(t))
	st, err := LoadFile(testdata(t, "valid", "full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := CanonicalYAML(st)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !strings.Contains(body, "testdata/secrets/token-admin") {
		t.Fatal("canonical YAML must include secret paths")
	}
	if strings.Contains(body, "abcdefghijklmnopqrstuvwxyz123456") {
		t.Fatal("canonical YAML must not include token bytes")
	}
	if strings.Contains(body, "alice-auth-pass") {
		t.Fatal("canonical YAML must not include USM secret bytes")
	}
}

func TestOmittedAllowClientCidrsLoopback(t *testing.T) {
	t.Chdir(repoRoot(t))
	st, err := LoadFile(testdata(t, "valid", "defaults.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Spec.Admission.AllowClientCidrs) != 2 {
		t.Fatalf("loopback default = %v", st.Spec.Admission.AllowClientCidrs)
	}
}
