package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/snmptest"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
)

func TestServeAnswersWithManagementOff(t *testing.T) {
	t.Chdir(repoRoot(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	errc := make(chan int, 1)
	go func() {
		errc <- serveWithContext(ctx, []string{
			"--config", "testdata/config/valid/full.yaml",
			"--snmp-listen", "127.0.0.1:0",
		}, pw, io.Discard)
		_ = pw.Close()
	}()
	lines := make(chan string, 16)
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
	var listen string
	deadline := time.After(5 * time.Second)
	for listen == "" {
		select {
		case line := <-lines:
			if strings.Contains(line, "trap listen=") || strings.Contains(line, "trap: bound") {
				t.Fatalf("trap must stay unbound: %q", line)
			}
			if strings.HasPrefix(line, "labsnmp snmp listen=") {
				listen = strings.TrimSpace(strings.TrimPrefix(line, "labsnmp snmp listen="))
			}
		case <-deadline:
			t.Fatal("missing snmp listen line")
		}
	}
	req := snmptest.MustEncodeGet(t, snmpwire.VersionV2c, "public", 1, snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0})
	m := snmptest.MustExchange(t, listen, req, 2*time.Second)
	p := m.RequestPDU()
	if p == nil || string(p.VarBinds[0].Value.Bytes) != "LabSNMP public-if" {
		t.Fatalf("%+v", p)
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
}

func TestServeMissingConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := serveCmd(nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
}
