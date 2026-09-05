package main

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/snmptest"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
)

func soakDuration(t *testing.T) time.Duration {
	t.Helper()
	d := 2 * time.Second
	if env := os.Getenv("LABSNMP_SOAK_DURATION"); env != "" {
		parsed, err := time.ParseDuration(env)
		if err != nil {
			t.Fatalf("LABSNMP_SOAK_DURATION: %v", err)
		}
		d = parsed
	}
	if testing.Short() && d > 500*time.Millisecond {
		d = 500 * time.Millisecond
	}
	if d < 50*time.Millisecond {
		d = 50 * time.Millisecond
	}
	return d
}

// TestSoakGETNEXTSETTrap drives GETNEXT + SET + trap against a live serve.
func TestSoakGETNEXTSETTrap(t *testing.T) {
	t.Chdir(repoRoot(t))
	d := soakDuration(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	var stderr strings.Builder
	errc := make(chan int, 1)
	go func() {
		errc <- serveWithContext(ctx, []string{
			"--config", "testdata/config/valid/soak.yaml",
			"--snmp-listen", "127.0.0.1:0",
			"--trap-listen", "127.0.0.1:0",
			"--management-listen", "off",
		}, pw, &stderr)
		_ = pw.Close()
	}()
	lines := make(chan string, 32)
	go func() {
		br := bufio.NewReader(pr)
		for {
			line, err := br.ReadString('\n')
			if line != "" {
				lines <- line
			}
			if err != nil {
				return
			}
		}
	}()
	var snmpAddr, trapAddr string
	deadline := time.After(5 * time.Second)
	for snmpAddr == "" || trapAddr == "" {
		select {
		case line := <-lines:
			if strings.HasPrefix(line, "labsnmp snmp listen=") {
				snmpAddr = strings.TrimSpace(strings.TrimPrefix(line, "labsnmp snmp listen="))
			}
			if strings.HasPrefix(line, "labsnmp trap listen=") {
				trapAddr = strings.TrimSpace(strings.TrimPrefix(line, "labsnmp trap listen="))
			}
		case code := <-errc:
			t.Fatalf("serve exited %d stderr=%s", code, stderr.String())
		case <-deadline:
			t.Fatalf("missing snmp/trap listen lines stderr=%s", stderr.String())
		}
	}

	end := time.Now().Add(d)
	ifOper := snmpwire.OID{1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1}
	sysDescr := snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0}
	cold := snmpwire.OID{1, 3, 6, 1, 6, 3, 1, 1, 5, 1}
	var walks, sets, traps int
	reqID := int32(1)
	for time.Now().Before(end) {
		reqID++
		req := snmptest.MustEncodeGetNext(t, snmpwire.VersionV2c, "public", reqID, snmpwire.OID{1, 3})
		m := snmptest.MustExchange(t, snmpAddr, req, 2*time.Second)
		p := m.RequestPDU()
		if p == nil || len(p.VarBinds) != 1 || !p.VarBinds[0].Name.Equal(sysDescr) {
			t.Fatalf("GETNEXT: %+v", p)
		}
		walks++

		reqID++
		setReq := snmptest.MustEncodeSet(t, snmpwire.VersionV2c, "private", reqID, []snmpwire.VarBind{{
			Name:  ifOper,
			Value: snmpwire.Int(2),
		}})
		sm := snmptest.MustExchange(t, snmpAddr, setReq, 2*time.Second)
		sp := sm.RequestPDU()
		if sp == nil || sp.ErrorStatus != snmpwire.ErrorStatusNoError {
			t.Fatalf("SET: %+v", sp)
		}
		sets++

		reqID++
		trap := snmptest.MustEncodeTrapV2(t, "public", reqID, cold)
		snmptest.MustSend(t, trapAddr, trap)
		traps++

		reqID++
		inform := snmptest.MustEncodeInform(t, "public", reqID, cold)
		im := snmptest.MustExchange(t, trapAddr, inform, time.Second)
		ip := im.RequestPDU()
		if ip == nil || ip.Type != snmpwire.PDUResponse || ip.RequestID != reqID {
			t.Fatalf("INFORM ack: %+v", ip)
		}
	}
	if walks < 1 || sets < 1 || traps < 1 {
		t.Fatalf("soak under-ran walks=%d sets=%d traps=%d dur=%s", walks, sets, traps, d)
	}

	cancel()
	select {
	case code := <-errc:
		if code != 0 {
			t.Fatalf("serve exit %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not exit")
	}
	t.Logf("soak serve GETNEXT+SET+trap dur=%s walks=%d sets=%d traps=%d", d, walks, sets, traps)
}
