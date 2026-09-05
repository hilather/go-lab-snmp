package snmpagent

import (
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/snmpwire"
)

func TestNetSNMPWalkPublicMapOnly(t *testing.T) {
	if _, err := exec.LookPath("snmpwalk"); err != nil {
		t.Skip("snmpwalk not installed")
	}
	s := startAgent(t, loadFull(t, nil))
	host := dst(s)
	sys := snmpwire.OID{1, 3, 6, 1, 2, 1, 1}.String()
	sysDescrOID := snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0}.String()
	privatePrefix := snmpwire.OID{1, 3, 6, 1, 4, 1, 99999}.String()
	out, err := exec.Command("snmpwalk", "-On", "-v2c", "-c", "public", "-t", "1", "-r", "0", host, sys).CombinedOutput()
	if err != nil {
		t.Fatalf("snmpwalk: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, sysDescrOID) {
		t.Fatalf("missing sysDescr:\n%s", text)
	}
	if strings.Contains(text, privatePrefix) {
		t.Fatalf("public walk leaked private map:\n%s", text)
	}
}

func TestNetSNMPV3DiscoveryGET(t *testing.T) {
	if _, err := exec.LookPath("snmpget"); err != nil {
		t.Skip("snmpget not installed")
	}
	s := startAgent(t, loadFull(t, nil))
	host := dst(s)
	priv := snmpwire.OID{1, 3, 6, 1, 4, 1, 99999, 1, 0}.String()
	cmd := exec.Command("snmpget",
		"-v3", "-l", "authPriv", "-u", "alice",
		"-a", "SHA-256", "-A", "alice-auth-pass",
		"-x", "AES", "-X", "alice-priv-pass",
		"-t", "2", "-r", "1",
		host, priv,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("snmpget v3: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "private-horizon") {
		t.Fatalf("v3 GET:\n%s", out)
	}
}

func TestNetSNMPGetWalkSet(t *testing.T) {
	if _, err := exec.LookPath("snmpget"); err != nil {
		t.Skip("snmpget not installed")
	}
	s := startAgent(t, loadYAML(t, rwYAML, nil))
	host := dst(s)
	sysDescrOID := snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0}.String()
	ifOperOID := snmpwire.OID{1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1}.String()
	out, err := exec.Command("snmpget", "-On", "-v2c", "-c", "public", "-t", "1", "-r", "0", host, sysDescrOID).CombinedOutput()
	if err != nil {
		t.Fatalf("snmpget: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "descr") {
		t.Fatalf("%s", out)
	}
	if _, err := exec.LookPath("snmpset"); err != nil {
		return
	}
	out, err = exec.Command("snmpset", "-On", "-v2c", "-c", "private", "-t", "1", "-r", "0", host, ifOperOID, "i", "2").CombinedOutput()
	if err != nil {
		t.Fatalf("snmpset: %v\n%s", err, out)
	}
	time.Sleep(20 * time.Millisecond)
	out, err = exec.Command("snmpget", "-On", "-v2c", "-c", "private", "-t", "1", "-r", "0", host, ifOperOID).CombinedOutput()
	if err != nil {
		t.Fatalf("snmpget after set: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), " INTEGER: 2") && !strings.Contains(string(out), "= INTEGER: 2") {
		t.Fatalf("after set:\n%s", out)
	}
}
