package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
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
	resp, err = http.Get("http://" + mgmt + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / %d (ui.enabled true must serve SPA 200)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("GET / content-type %q (want text/html SPA)", ct)
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

func TestParseServeFlagsShutdownAndPID(t *testing.T) {
	f, err := parseServeFlags([]string{"--config", "x.yaml"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if f.ShutdownTimeout != defaultShutdownTimeout || defaultShutdownTimeout != 10*time.Second {
		t.Fatalf("shutdown-timeout default %s, want 10s", f.ShutdownTimeout)
	}
	if f.PIDFile != "" {
		t.Fatalf("pid-file default %q", f.PIDFile)
	}
	if f.ManagementListen != "off" {
		t.Fatalf("management-listen default %q", f.ManagementListen)
	}
	if f.DTLSListen != "" || f.DTLSTrapListen != "" {
		t.Fatalf("dtls flags default %q %q", f.DTLSListen, f.DTLSTrapListen)
	}
	f, err = parseServeFlags([]string{
		"--config", "x.yaml",
		"--shutdown-timeout", "3s",
		"--pid-file", "/tmp/labsnmp.pid",
		"--dtls-listen", "127.0.0.1:2161",
		"--dtls-trap-listen", "off",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if f.ShutdownTimeout != 3*time.Second {
		t.Fatalf("shutdown-timeout %s", f.ShutdownTimeout)
	}
	if f.PIDFile != "/tmp/labsnmp.pid" {
		t.Fatalf("pid-file %q", f.PIDFile)
	}
	if f.DTLSListen != "127.0.0.1:2161" {
		t.Fatalf("dtls-listen %q", f.DTLSListen)
	}
	if f.DTLSTrapListen != "off" {
		t.Fatalf("dtls-trap-listen %q", f.DTLSTrapListen)
	}
}

func TestParseServeFlagsNoTCPListen(t *testing.T) {
	_, err := parseServeFlags([]string{"--config", "x.yaml", "--tcp-listen", ":161"}, io.Discard)
	if err == nil {
		t.Fatal("expected error for --tcp-listen")
	}
}

func TestServeWritesPIDFile(t *testing.T) {
	t.Chdir(repoRoot(t))
	pidPath := filepath.Join(t.TempDir(), "labsnmp.pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	errc := make(chan int, 1)
	go func() {
		errc <- serveWithContext(ctx, []string{
			"--config", "testdata/config/valid/full.yaml",
			"--snmp-listen", "127.0.0.1:0",
			"--trap-listen", "off",
			"--pid-file", pidPath,
			"--shutdown-timeout", "2s",
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
	deadline := time.After(5 * time.Second)
	bound := false
	for !bound {
		select {
		case line := <-lines:
			if strings.HasPrefix(line, "labsnmp snmp listen=") {
				bound = true
			}
		case <-deadline:
			t.Fatal("missing snmp listen line")
		}
	}
	var raw []byte
	var err error
	for i := 0; i < 50; i++ {
		raw, err = os.ReadFile(pidPath)
		if err == nil && len(bytes.TrimSpace(raw)) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid < 1 {
		t.Fatalf("pid-file %q", raw)
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
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Fatalf("pid-file still present after shutdown: %v", err)
	}
}

func TestServePIDFileWriteFailure(t *testing.T) {
	t.Chdir(repoRoot(t))
	pidPath := filepath.Join(t.TempDir(), "missing", "labsnmp.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	code := serveWithContext(ctx, []string{
		"--config", "testdata/config/valid/full.yaml",
		"--snmp-listen", "127.0.0.1:0",
		"--trap-listen", "off",
		"--pid-file", pidPath,
		"--shutdown-timeout", "2s",
	}, io.Discard, &stderr)
	if code != 1 {
		t.Fatalf("exit %d, want 1 stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "pid-file") {
		t.Fatalf("stderr %q", stderr.String())
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

func TestServeUIEnabledIsHTML(t *testing.T) {
	addr := serveWithUI(t, true)
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / code=%d body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type=%q", ct)
	}
	if !strings.Contains(string(body), "LabSNMP") {
		t.Fatalf("body=%s", body)
	}
}

func TestServeUIDisabledIs404(t *testing.T) {
	addr := serveWithUI(t, false)
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET / code=%d body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "problem+json") {
		t.Fatalf("content-type=%q body=%s", ct, body)
	}
	if strings.Contains(string(body), "<!doctype") {
		t.Fatalf("disabled UI served HTML: %s", body)
	}
}

func TestResetMovesAgentPacketConn(t *testing.T) {
	t.Chdir(repoRoot(t))
	agent1 := freeUDPAddr(t)
	agent2 := freeUDPAddr(t)
	trap := freeUDPAddr(t)
	mgmtLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mgmt := mgmtLn.Addr().String()
	_ = mgmtLn.Close()

	cfg := writeBootstrap(t, func(body string) string {
		body = strings.Replace(body, `address: ":161"`, `address: "`+agent1+`"`, 1)
		body = strings.Replace(body, `address: ":162"`, `address: "`+trap+`"`, 1)
		return body
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	errc := make(chan int, 1)
	go func() {
		errc <- serveWithContext(ctx, []string{
			"--config", cfg,
			"--management-listen", mgmt,
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
	var snmpListen, mgmtListen string
	deadline := time.After(5 * time.Second)
	for snmpListen == "" || mgmtListen == "" {
		select {
		case line := <-lines:
			if strings.HasPrefix(line, "labsnmp snmp listen=") {
				snmpListen = strings.TrimSpace(strings.TrimPrefix(line, "labsnmp snmp listen="))
			}
			if strings.HasPrefix(line, "labsnmp management listen=") {
				mgmtListen = strings.TrimSpace(strings.TrimPrefix(line, "labsnmp management listen="))
			}
		case <-deadline:
			t.Fatal("missing snmp/management listen line")
		}
	}
	if snmpListen != agent1 {
		t.Fatalf("initial listen %s want %s", snmpListen, agent1)
	}

	req := snmptest.MustEncodeGet(t, snmpwire.VersionV2c, "public", 1, snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0})
	m := snmptest.MustExchange(t, agent1, req, 2*time.Second)
	p := m.RequestPDU()
	if p == nil || string(p.VarBinds[0].Value.Bytes) != "LabSNMP public-if" {
		t.Fatalf("before reset %+v", p)
	}

	body, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(body), `address: "`+agent1+`"`, `address: "`+agent2+`"`, 1)
	if rewritten == string(body) {
		t.Fatal("rewrite agent.address")
	}
	if err := os.WriteFile(cfg, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, "http://"+mgmtListen+"/v1/state:reset", strings.NewReader(`{"reason":"rebind"}`))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer abcdefghijklmnopqrstuvwxyz123456")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("reset %d %s", resp.StatusCode, b)
	}

	m = snmptest.MustExchange(t, agent2, req, 2*time.Second)
	p = m.RequestPDU()
	if p == nil || string(p.VarBinds[0].Value.Bytes) != "LabSNMP public-if" {
		t.Fatalf("after reset %+v", p)
	}
	hold, err := net.ListenPacket("udp", agent1)
	if err != nil {
		t.Fatalf("old PacketConn must have moved: %v", err)
	}
	_ = hold.Close()

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

func TestDesiredListenersTCPOnly(t *testing.T) {
	snap := &snapshot.Snapshot{
		TCPEnabled: true,
		TCPAddress: ":1161",
	}
	d := desiredListeners(serveFlags{}, snap, "")
	if d.AgentUDP != "" {
		t.Fatalf("udp must be off: %+v", d)
	}
	if d.AgentTCP != ":1161" {
		t.Fatalf("tcp: %+v", d)
	}
	if d.TrapTCP != "" {
		t.Fatalf("trap tcp must be off: %+v", d)
	}
}

func TestDesiredListenersTCPInherit(t *testing.T) {
	snap := &snapshot.Snapshot{
		AgentEnabled: true,
		AgentAddress: "127.0.0.1:1161",
		TrapsEnabled: true,
		TrapAddress:  "127.0.0.1:1162",
		TCPEnabled:   true,
	}
	d := desiredListeners(serveFlags{SNMPListen: "127.0.0.1:2161"}, snap, "")
	if d.AgentUDP != "127.0.0.1:2161" || d.AgentTCP != "127.0.0.1:2161" {
		t.Fatalf("inherit flag UDP: %+v", d)
	}
	if d.TrapUDP != "127.0.0.1:1162" || d.TrapTCP != "127.0.0.1:1162" {
		t.Fatalf("trap inherit: %+v", d)
	}
	off := desiredListeners(serveFlags{SNMPListen: "off"}, snap, "")
	if off.AgentUDP != "" || off.AgentTCP != "" {
		t.Fatalf("udp off and empty tcp.address: %+v", off)
	}
}

func TestDesiredListenersDTLSFlags(t *testing.T) {
	snap := &snapshot.Snapshot{
		AgentEnabled:     true,
		AgentAddress:     ":161",
		DTLSEnabled:      true,
		DTLSAddress:      ":10161",
		DTLSTrapsAddress: ":10162",
		DTLSCertFile:     "cert.pem",
		DTLSKeyFile:      "key.pem",
	}
	d := desiredListeners(serveFlags{SNMPListen: "off", DTLSListen: "127.0.0.1:2161", DTLSTrapListen: "off"}, snap, "")
	if d.AgentUDP != "" {
		t.Fatalf("udp off: %+v", d)
	}
	if d.AgentDTLS != "127.0.0.1:2161" {
		t.Fatalf("dtls flag: %+v", d)
	}
	if d.TrapDTLS != "" {
		t.Fatalf("trap dtls off: %+v", d)
	}
	if d.DTLSCertFile != "cert.pem" || d.DTLSKeyFile != "key.pem" {
		t.Fatalf("creds: %+v", d)
	}
}

func TestServeUDPOffNoAgentPlaneExits(t *testing.T) {
	t.Chdir(repoRoot(t))
	var stderr bytes.Buffer
	code := serveWithContext(context.Background(), []string{
		"--config", "testdata/config/valid/full.yaml",
		"--snmp-listen", "off",
		"--trap-listen", "off",
	}, io.Discard, &stderr)
	if code != 1 {
		t.Fatalf("exit %d, want 1 stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "no agent-plane listener will bind") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

func TestServeEnabledBindFailureExits(t *testing.T) {
	t.Chdir(repoRoot(t))
	hold, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	var stderr bytes.Buffer
	code := serveWithContext(context.Background(), []string{
		"--config", "testdata/config/valid/full.yaml",
		"--snmp-listen", hold.LocalAddr().String(),
		"--trap-listen", "off",
	}, io.Discard, &stderr)
	if code != 1 {
		t.Fatalf("exit %d, want 1 stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "listen") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

func TestServeTCPOnlyStarts(t *testing.T) {
	t.Chdir(repoRoot(t))
	tcp := freeTCPAddr(t)
	cfg := writeBootstrap(t, func(body string) string {
		body = strings.Replace(body, "    agent:\n      enabled: true\n      address: \":161\"",
			"    agent:\n      enabled: false", 1)
		body = strings.Replace(body, "    tcp:\n      enabled: false",
			"    tcp:\n      enabled: true\n      address: \""+tcp+"\"", 1)
		return body
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	errc := make(chan int, 1)
	go func() {
		errc <- serveWithContext(ctx, []string{"--config", cfg, "--trap-listen", "off"}, pw, io.Discard)
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
	var tcpListen string
	deadline := time.After(5 * time.Second)
	for tcpListen == "" {
		select {
		case line := <-lines:
			if strings.HasPrefix(line, "labsnmp snmp listen=") {
				t.Fatalf("UDP agent must stay unbound: %q", line)
			}
			if strings.HasPrefix(line, "labsnmp snmp tcp listen=") {
				tcpListen = strings.TrimSpace(strings.TrimPrefix(line, "labsnmp snmp tcp listen="))
			}
		case code := <-errc:
			t.Fatalf("serve exited %d", code)
		case <-deadline:
			t.Fatal("missing snmp tcp listen line")
		}
	}
	req := snmptest.MustEncodeGet(t, snmpwire.VersionV2c, "public", 1, snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0})
	c, err := net.DialTimeout("tcp", tcpListen, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	if err := snmpwire.WriteTCP(c, req); err != nil {
		t.Fatal(err)
	}
	raw, err := snmpwire.ReadTCP(c, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	m := snmptest.MustDecode(t, raw)
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

func TestServeDTLSUDPOffStarts(t *testing.T) {
	t.Chdir(repoRoot(t))
	dtls := freeUDPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	errc := make(chan int, 1)
	go func() {
		errc <- serveWithContext(ctx, []string{
			"--config", "testdata/config/valid/dtls-enabled.yaml",
			"--snmp-listen", "off",
			"--trap-listen", "off",
			"--dtls-listen", dtls,
			"--dtls-trap-listen", "off",
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
	var dtlsListen string
	deadline := time.After(5 * time.Second)
	for dtlsListen == "" {
		select {
		case line := <-lines:
			if strings.HasPrefix(line, "labsnmp snmp listen=") {
				t.Fatalf("UDP agent must stay unbound: %q", line)
			}
			if strings.HasPrefix(line, "labsnmp snmp dtls listen=") {
				dtlsListen = strings.TrimSpace(strings.TrimPrefix(line, "labsnmp snmp dtls listen="))
			}
		case code := <-errc:
			t.Fatalf("serve exited %d", code)
		case <-deadline:
			t.Fatal("missing snmp dtls listen line")
		}
	}
	if dtlsListen == "" {
		t.Fatal("empty dtls listen")
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

func TestServeTCPBindFailureExits(t *testing.T) {
	t.Chdir(repoRoot(t))
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	cfg := writeBootstrap(t, func(body string) string {
		body = strings.Replace(body, "    agent:\n      enabled: true\n      address: \":161\"",
			"    agent:\n      enabled: false", 1)
		body = strings.Replace(body, "    tcp:\n      enabled: false",
			"    tcp:\n      enabled: true\n      address: \""+hold.Addr().String()+"\"", 1)
		return body
	})
	var stderr bytes.Buffer
	code := serveWithContext(context.Background(), []string{"--config", cfg}, io.Discard, &stderr)
	if code != 1 {
		t.Fatalf("exit %d, want 1 stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "listen") {
		t.Fatalf("stderr %q", stderr.String())
	}
}

func writeBootstrap(t *testing.T, mutate func(string) string) string {
	return writeNamedBootstrap(t, "full.yaml", mutate)
}

func writeNamedBootstrap(t *testing.T, name string, mutate func(string) string) string {
	t.Helper()
	root := repoRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "testdata", "config", "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	secrets := filepath.Join(root, "testdata", "secrets") + string(os.PathSeparator)
	certs := filepath.Join(root, "testdata", "certs") + string(os.PathSeparator)
	body := strings.ReplaceAll(string(src), "testdata/secrets/", secrets)
	body = strings.ReplaceAll(body, "testdata/certs/", certs)
	if mutate != nil {
		body = mutate(body)
	}
	cfg := filepath.Join(t.TempDir(), "labsnmp.yaml")
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func serveWithUI(t *testing.T, uiEnabled bool) string {
	t.Helper()
	root := repoRoot(t)
	t.Chdir(root)
	src, err := os.ReadFile(filepath.Join(root, "testdata", "config", "valid", "full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	secrets := filepath.Join(root, "testdata", "secrets") + string(os.PathSeparator)
	body := strings.ReplaceAll(string(src), "testdata/secrets/", secrets)
	want := "enabled: true"
	if !uiEnabled {
		want = "enabled: false"
	}
	body = strings.Replace(body, "  ui:\n    enabled: true", "  ui:\n    "+want, 1)
	cfg := filepath.Join(t.TempDir(), "labsnmp.yaml")
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mgmtAddr := httpLn.Addr().String()
	_ = httpLn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var stdout, stderr strings.Builder
	errCh := make(chan int, 1)
	go func() {
		errCh <- serveWithContext(ctx, []string{
			"--config", cfg,
			"--snmp-listen", "127.0.0.1:0",
			"--trap-listen", "127.0.0.1:0",
			"--management-listen", mgmtAddr,
		}, &stdout, &stderr)
	}()

	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		select {
		case code := <-errCh:
			t.Fatalf("serve exited %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		default:
		}
		resp, err := http.Get("http://" + mgmtAddr + "/v1/health/live")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return mgmtAddr
			}
			last = fmt.Errorf("live status %d", resp.StatusCode)
		} else {
			last = err
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("management never became live: %v stdout=%q stderr=%q", last, stdout.String(), stderr.String())
	return ""
}
