package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/model"
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
			"--trap-listen", "127.0.0.1:0",
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
	var listen, trapListen string
	var mgmtNotBound bool
	deadline := time.After(5 * time.Second)
	for listen == "" || trapListen == "" || !mgmtNotBound {
		select {
		case line := <-lines:
			if strings.HasPrefix(line, "labsnmp snmp listen=") {
				listen = strings.TrimSpace(strings.TrimPrefix(line, "labsnmp snmp listen="))
			}
			if strings.HasPrefix(line, "labsnmp trap listen=") {
				trapListen = strings.TrimSpace(strings.TrimPrefix(line, "labsnmp trap listen="))
			}
			if strings.Contains(line, "management listen=") {
				t.Fatalf("management must stay unbound: %q", line)
			}
			if strings.Contains(line, "management: not bound") {
				mgmtNotBound = true
			}
		case <-deadline:
			t.Fatal("missing snmp/trap listen or management not-bound line")
		}
	}
	req := snmptest.MustEncodeGet(t, snmpwire.VersionV2c, "public", 1, snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0})
	m := snmptest.MustExchange(t, listen, req, 2*time.Second)
	p := m.RequestPDU()
	if p == nil || string(p.VarBinds[0].Value.Bytes) != "LabSNMP public-if" {
		t.Fatalf("%+v", p)
	}
	trap := snmptest.MustEncodeTrapV2(t, "public", 2, snmpwire.OID{1, 3, 6, 1, 6, 3, 1, 1, 5, 1})
	snmptest.MustSend(t, trapListen, trap)
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

func TestServeTrapListenOffUnbound(t *testing.T) {
	t.Chdir(repoRoot(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	errc := make(chan int, 1)
	go func() {
		errc <- serveWithContext(ctx, []string{
			"--config", "testdata/config/valid/full.yaml",
			"--snmp-listen", "127.0.0.1:0",
			"--trap-listen", "off",
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
	var sawNotBound bool
	deadline := time.After(5 * time.Second)
	for !sawNotBound {
		select {
		case line := <-lines:
			if strings.Contains(line, "trap listen=") {
				t.Fatalf("trap must stay unbound: %q", line)
			}
			if strings.Contains(line, "trap: not bound") {
				sawNotBound = true
			}
		case <-deadline:
			t.Fatal("missing trap not-bound line")
		}
	}
	cancel()
	select {
	case <-errc:
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not exit")
	}
}

func TestServeBindsManagementListen(t *testing.T) {
	t.Chdir(repoRoot(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	errc := make(chan int, 1)
	go func() {
		errc <- serveWithContext(ctx, []string{
			"--config", "testdata/config/valid/full.yaml",
			"--snmp-listen", "127.0.0.1:0",
			"--trap-listen", "off",
			"--management-listen", "127.0.0.1:0",
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
	var mgmt string
	deadline := time.After(5 * time.Second)
	for mgmt == "" {
		select {
		case line := <-lines:
			if strings.HasPrefix(line, "labsnmp management listen=") {
				mgmt = strings.TrimSpace(strings.TrimPrefix(line, "labsnmp management listen="))
			}
		case <-deadline:
			t.Fatal("missing management listen line")
		}
	}
	resp, err := http.Get("http://" + mgmt + "/v1/health/live")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("live %d", resp.StatusCode)
	}
	resp, err = http.Get("http://" + mgmt + "/v1/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ready %d (agent bound, trap off, management bound)", resp.StatusCode)
	}
	var hcOut, hcErr strings.Builder
	if code := healthcheckCmd([]string{"--url", "http://" + mgmt + "/v1/health/ready"}, &hcOut, &hcErr); code != 0 {
		t.Fatalf("healthcheck exit %d stderr=%s", code, hcErr.String())
	}
	resp, err = http.Get("http://" + mgmt + "/v1/version")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("version %d (SEC-001 must 401 without bearer)", resp.StatusCode)
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+mgmt+"/v1/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer abcdefghijklmnopqrstuvwxyz123456")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("version with bearer %d", resp.StatusCode)
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

func TestServeTrapListenBinds(t *testing.T) {
	t.Chdir(repoRoot(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	errc := make(chan int, 1)
	go func() {
		errc <- serveWithContext(ctx, []string{
			"--config", "testdata/config/valid/full.yaml",
			"--snmp-listen", "127.0.0.1:0",
			"--trap-listen", "127.0.0.1:0",
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
	var trapListen string
	deadline := time.After(5 * time.Second)
	for trapListen == "" {
		select {
		case line := <-lines:
			if strings.HasPrefix(line, "labsnmp trap listen=") {
				trapListen = strings.TrimSpace(strings.TrimPrefix(line, "labsnmp trap listen="))
			}
		case <-deadline:
			t.Fatal("missing trap listen line")
		}
	}
	req := snmptest.MustEncodeInform(t, "public", 15, snmpwire.OID{1, 3, 6, 1, 6, 3, 1, 1, 5, 1})
	m := snmptest.MustExchange(t, trapListen, req, 2*time.Second)
	p := m.RequestPDU()
	if p == nil || p.Type != snmpwire.PDUResponse || p.RequestID != 15 {
		t.Fatalf("INFORM ack %+v", p)
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

func TestResolveTrapListen(t *testing.T) {
	if addr, on := resolveTrapListen("off", nil); on || addr != "" {
		t.Fatalf("off: %s %v", addr, on)
	}
	if addr, on := resolveTrapListen("127.0.0.1:1162", nil); !on || addr != "127.0.0.1:1162" {
		t.Fatalf("flag: %s %v", addr, on)
	}
	yamlOn := &model.State{}
	yamlOn.Spec.Listeners.Traps.Enabled = true
	yamlOn.Spec.Listeners.Traps.Address = ":162"
	if addr, on := resolveTrapListen("", yamlOn); !on || addr != ":162" {
		t.Fatalf("yaml on: %s %v", addr, on)
	}
	if addr, on := resolveTrapListen("off", yamlOn); on || addr != "" {
		t.Fatalf("flag off wins: %s %v", addr, on)
	}
	yamlOff := &model.State{}
	yamlOff.Spec.Listeners.Traps.Enabled = false
	yamlOff.Spec.Listeners.Traps.Address = ":162"
	if addr, on := resolveTrapListen("", yamlOff); on || addr != "" {
		t.Fatalf("yaml off: %s %v", addr, on)
	}
	if addr, on := resolveTrapListen("127.0.0.1:0", yamlOff); !on || addr != "127.0.0.1:0" {
		t.Fatalf("flag wins over yaml off: %s %v", addr, on)
	}
}

func TestTrapListenAddressStillFreeWhenOff(t *testing.T) {
	t.Chdir(repoRoot(t))
	const trapAddr = "127.0.0.1:26162"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan int, 1)
	go func() {
		errc <- serveWithContext(ctx, []string{
			"--config", "testdata/config/valid/full.yaml",
			"--snmp-listen", "127.0.0.1:0",
			"--trap-listen", "off",
		}, io.Discard, io.Discard)
	}()
	time.Sleep(50 * time.Millisecond)
	pc, err := net.ListenPacket("udp", trapAddr)
	if err != nil {
		t.Fatalf("trap address must stay unbound: %v", err)
	}
	_ = pc.Close()
	cancel()
	select {
	case <-errc:
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not exit")
	}
}
