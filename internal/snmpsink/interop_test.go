package snmpsink

import (
	"os/exec"
	"testing"
	"time"
)

func TestNetSNMPTrap(t *testing.T) {
	if _, err := exec.LookPath("snmptrap"); err != nil {
		t.Skip("snmptrap not installed")
	}
	s := startSink(t, Config{})
	host := dst(s)
	out, err := exec.Command("snmptrap", "-v2c", "-c", "public", "-t", "1", "-r", "0",
		host, "", "1.3.6.1.6.3.1.1.5.1").CombinedOutput()
	if err != nil {
		t.Fatalf("snmptrap: %v\n%s", err, out)
	}
	rec := waitOne(t, s)
	if rec.PDUType != "trapv2" || rec.Community != "public" {
		t.Fatalf("%+v", rec)
	}
}

func TestNetSNMPInform(t *testing.T) {
	if _, err := exec.LookPath("snmpinform"); err != nil {
		t.Skip("snmpinform not installed")
	}
	s := startSink(t, Config{})
	host := dst(s)
	out, err := exec.Command("snmpinform", "-v2c", "-c", "public", "-t", "2", "-r", "0",
		host, "", "1.3.6.1.6.3.1.1.5.1").CombinedOutput()
	if err != nil {
		t.Fatalf("snmpinform: %v\n%s", err, out)
	}
	time.Sleep(20 * time.Millisecond)
	if s.InformAck.Load() < 1 {
		t.Fatal("InformAck")
	}
	rec := waitOne(t, s)
	if rec.PDUType != "inform" {
		t.Fatalf("%+v", rec)
	}
}
