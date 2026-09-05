package config

import (
	"math"
	"os"
	"path/filepath"
	"strings"
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

func TestTLSUnsupportedRemainsInCatalog(t *testing.T) {
	found := false
	for _, c := range domainerr.Codes() {
		if c == domainerr.CodeTLSUnsupported {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("tls_unsupported must remain in the domainerr catalog")
	}
}

func TestTCPEnabledValidates(t *testing.T) {
	t.Chdir(repoRoot(t))
	for _, name := range []string{"tcp-enabled.yaml", "tcp-only.yaml"} {
		t.Run(name, func(t *testing.T) {
			st, err := LoadFile(testdata(t, "valid", name))
			if err != nil {
				t.Fatal(err)
			}
			if !st.Spec.Listeners.TCP.Enabled {
				t.Fatal("tcp.enabled want true")
			}
			if name == "tcp-only.yaml" && st.Spec.Listeners.Agent.Enabled {
				t.Fatal("tcp-only must keep UDP agent off")
			}
		})
	}
}

func TestDTLSEnabledValidates(t *testing.T) {
	t.Chdir(repoRoot(t))
	st, err := LoadFile(testdata(t, "valid", "dtls-enabled.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !st.Spec.Listeners.DTLS.Enabled {
		t.Fatal("dtls.enabled want true")
	}
	if st.Spec.Listeners.DTLS.Address != DefaultDTLSAddress {
		t.Fatalf("dtls.address=%q want %q", st.Spec.Listeners.DTLS.Address, DefaultDTLSAddress)
	}
	if st.Spec.Listeners.DTLS.TrapsAddress != DefaultDTLSTrapsAddress {
		t.Fatalf("dtls.trapsAddress=%q want %q", st.Spec.Listeners.DTLS.TrapsAddress, DefaultDTLSTrapsAddress)
	}
}

func TestTCPOnlyRequiresIdentity(t *testing.T) {
	t.Chdir(repoRoot(t))
	_, err := LoadFile(testdata(t, "invalid", "tcp-only-no-identity.yaml"))
	de := requireValidation(t, err, violationRequired)
	if de.Code != domainerr.CodeValidationFailed {
		t.Fatalf("code=%s want validation_failed", de.Code)
	}
	found := false
	for _, v := range de.FieldViolations {
		if v.Path == "spec" && v.Code == violationRequired {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("want spec required in %+v", de.FieldViolations)
	}
}

func TestDTLSRequiresCert(t *testing.T) {
	t.Chdir(repoRoot(t))
	_, err := LoadFile(testdata(t, "invalid", "dtls-enabled-no-cert.yaml"))
	de := requireValidation(t, err, violationRequired)
	if de.Code == domainerr.CodeTLSUnsupported {
		t.Fatal("missing certs must not emit tls_unsupported")
	}
	var cert, key bool
	for _, v := range de.FieldViolations {
		if v.Path == "spec.listeners.dtls.certFile" && v.Code == violationRequired {
			cert = true
		}
		if v.Path == "spec.listeners.dtls.keyFile" && v.Code == violationRequired {
			key = true
		}
	}
	if !cert || !key {
		t.Fatalf("want certFile and keyFile required in %+v", de.FieldViolations)
	}
}

func TestDTLSBadPEM(t *testing.T) {
	t.Chdir(repoRoot(t))
	_, err := LoadFile(testdata(t, "invalid", "dtls-bad-pem.yaml"))
	de := requireValidation(t, err, violationInvalidValue)
	if de.Code == domainerr.CodeTLSUnsupported {
		t.Fatal("bad PEM must not emit tls_unsupported")
	}
}

func TestListenersTLSUnknownField(t *testing.T) {
	t.Chdir(repoRoot(t))
	_, err := LoadFile(testdata(t, "invalid", "listeners-tls.yaml"))
	de := requireValidation(t, err, violationUnknownField)
	if de.Code != domainerr.CodeUnknownField {
		t.Fatalf("code=%s want unknown_field", de.Code)
	}
	found := false
	for _, v := range de.FieldViolations {
		if strings.Contains(v.Path, "tls") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("want listeners.tls in %+v", de.FieldViolations)
	}
}

func TestDTLSUDPCollision(t *testing.T) {
	t.Chdir(repoRoot(t))
	_, err := LoadFile(testdata(t, "invalid", "dtls-udp-collision.yaml"))
	de := requireValidation(t, err, violationInvalidValue)
	found := false
	for _, v := range de.FieldViolations {
		if v.Path == "spec.listeners.dtls.address" && v.Code == violationInvalidValue {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("want dtls.address invalid_value in %+v", de.FieldViolations)
	}
}

func TestDTLSTrapUDPCollision(t *testing.T) {
	t.Chdir(repoRoot(t))
	body := `apiVersion: labsnmp.dev/v1alpha1
kind: LabSNMP
metadata:
  name: x
spec:
  listeners:
    traps:
      enabled: true
      address: ":162"
    dtls:
      enabled: true
      trapsAddress: "0.0.0.0:162"
      certFile: testdata/certs/lab.pem
      keyFile: testdata/certs/lab-key.pem
  maps:
    - name: system-if
      objects:
        - oid: "10.20.0.3.10.20.0.5.0"
          type: octetString
          value: "x"
  communities:
    - name: public
      communityFile: testdata/secrets/snmp-public
      map: system-if
`
	_, err := Load([]byte(body))
	de := requireValidation(t, err, violationInvalidValue)
	found := false
	for _, v := range de.FieldViolations {
		if v.Path == "spec.listeners.dtls.trapsAddress" && v.Code == violationInvalidValue {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("want dtls.trapsAddress invalid_value in %+v", de.FieldViolations)
	}
}

func TestTCPEnabledBothPlanesOff(t *testing.T) {
	t.Chdir(repoRoot(t))
	_, err := LoadFile(testdata(t, "invalid", "tcp-enabled-no-address.yaml"))
	de := requireValidation(t, err, violationRequired)
	found := false
	for _, v := range de.FieldViolations {
		if v.Path == "spec.listeners.tcp.enabled" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("want spec.listeners.tcp.enabled in %+v", de.FieldViolations)
	}
}

func TestDTLSCertsResolveFromBaseDir(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()
	for _, name := range []string{"lab.pem", "lab-key.pem"} {
		b, err := os.ReadFile(filepath.Join(root, "testdata", "certs", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "community"), []byte("public\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	body := `apiVersion: labsnmp.dev/v1alpha1
kind: LabSNMP
metadata:
  name: x
spec:
  listeners:
    agent:
      enabled: false
    dtls:
      enabled: true
      certFile: lab.pem
      keyFile: lab-key.pem
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
	if !st.Spec.Listeners.DTLS.Enabled {
		t.Fatal("dtls.enabled want true")
	}
}

func TestDTLSClientCAValid(t *testing.T) {
	t.Chdir(repoRoot(t))
	body := `apiVersion: labsnmp.dev/v1alpha1
kind: LabSNMP
metadata:
  name: x
spec:
  listeners:
    dtls:
      enabled: true
      certFile: testdata/certs/lab.pem
      keyFile: testdata/certs/lab-key.pem
      clientCAFile: testdata/certs/lab.pem
  maps:
    - name: system-if
      objects:
        - oid: "10.20.0.3.10.20.0.5.0"
          type: octetString
          value: "x"
  communities:
    - name: public
      communityFile: testdata/secrets/snmp-public
      map: system-if
`
	st, err := Load([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if st.Spec.Listeners.DTLS.ClientCAFile == "" {
		t.Fatal("clientCAFile dropped")
	}
}

func TestDTLSCertFileMissing(t *testing.T) {
	t.Chdir(repoRoot(t))
	body := `apiVersion: labsnmp.dev/v1alpha1
kind: LabSNMP
metadata:
  name: x
spec:
  listeners:
    dtls:
      enabled: true
      certFile: testdata/certs/no-such.pem
      keyFile: testdata/certs/lab-key.pem
  maps:
    - name: system-if
      objects:
        - oid: "10.20.0.3.10.20.0.5.0"
          type: octetString
          value: "x"
  communities:
    - name: public
      communityFile: testdata/secrets/snmp-public
      map: system-if
`
	_, err := Load([]byte(body))
	de := requireValidation(t, err, violationInvalidValue)
	if de.Code == domainerr.CodeTLSUnsupported {
		t.Fatal("missing cert file must not emit tls_unsupported")
	}
}

func TestCanonicalUDPAddrUnspecified(t *testing.T) {
	a, okA := canonicalUDPAddr(":161")
	b, okB := canonicalUDPAddr("0.0.0.0:161")
	if !okA || !okB || a != b {
		t.Fatalf("canonical :161=%q 0.0.0.0:161=%q", a, b)
	}
	c, okC := canonicalUDPAddr("127.0.0.1:161")
	if !okC || c == a {
		t.Fatalf("127.0.0.1:161=%q must differ from unspecified", c)
	}
}
