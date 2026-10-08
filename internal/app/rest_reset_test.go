package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/auth"
	"github.com/hilather/go-lab-snmp/internal/control/rest"
	"github.com/hilather/go-lab-snmp/internal/model"
)

// TestRESTResetManagementOffAndMove drives a real management listener.
// package app_test can import rest and the test-only trap-policy hook
// without an import cycle (rest already imports app).
func TestRESTResetManagementOffAndMove(t *testing.T) {
	t.Run("off", func(t *testing.T) {
		svc, srv, token, addr, path, serveErr := bootRESTMgmt(t)
		beforeGen := svc.Active().Generation
		rewriteMgmt(t, path, addr, "")

		status, body, elapsed := postReset(t, addr, token)
		if elapsed >= time.Second || status != http.StatusOK {
			t.Fatalf("reset status %d in %s, want 200 in < 1s; body %v", status, elapsed, body)
		}
		if body["applied"] != true {
			t.Fatalf("applied %v, want true", body["applied"])
		}
		if body["generation"] != float64(beforeGen+1) {
			t.Fatalf("generation %v, want %v", body["generation"], beforeGen+1)
		}
		if got := svc.Active().ManagementAddress; got != "" {
			t.Fatalf("management address %q, want empty", got)
		}
		if srv.Bound() {
			t.Fatal("Bound after management off")
		}
		assertRefused(t, addr)
		assertServeClosed(t, serveErr)
	})

	t.Run("move", func(t *testing.T) {
		svc, srv, token, addr, path, serveErr := bootRESTMgmt(t)
		beforeGen := svc.Active().Generation
		next := freeAddr(t)
		rewriteMgmt(t, path, addr, next)

		status, body, elapsed := postReset(t, addr, token)
		if elapsed >= time.Second || status != http.StatusOK {
			t.Fatalf("reset status %d in %s, want 200 in < 1s; body %v", status, elapsed, body)
		}
		if body["applied"] != true {
			t.Fatalf("applied %v, want true", body["applied"])
		}
		if body["generation"] != float64(beforeGen+1) {
			t.Fatalf("generation %v, want %v", body["generation"], beforeGen+1)
		}
		if got := svc.Active().ManagementAddress; got != next {
			t.Fatalf("management address %q, want %q", got, next)
		}
		if !srv.Bound() {
			t.Fatal("Bound after management move")
		}
		if got := srv.Addr(); got != next {
			t.Fatalf("Addr %q, want %q", got, next)
		}
		assertHealth(t, next)
		assertRefused(t, addr)
		assertServeClosed(t, serveErr)
	})

	t.Run("failure", func(t *testing.T) {
		svc, srv, token, addr, path, serveErr := bootRESTMgmt(t)
		beforeRev := svc.Active().Revision
		beforeAddr := svc.Active().ManagementAddress
		next := freeAddr(t)
		rewriteMgmt(t, path, addr, next)
		svc.SetTrapPolicyFailForTest(errors.New("replace caps failed"))

		status, body, elapsed := postReset(t, addr, token)
		t.Logf("failure body %v", body)
		if elapsed >= time.Second {
			t.Fatalf("reset took %s, want < 1s (status %d)", elapsed, status)
		}
		if status/100 == 2 {
			t.Fatalf("status %d, want non-2xx; body %v", status, body)
		}
		if got := svc.Active().ManagementAddress; got != beforeAddr {
			t.Fatalf("management address %q, want %q", got, beforeAddr)
		}
		if svc.Active().Revision != beforeRev {
			t.Fatalf("revision changed %s -> %s", beforeRev, svc.Active().Revision)
		}
		assertHealth(t, addr)
		assertRefused(t, next)
		if srv.Addr() != addr || !srv.Bound() {
			t.Fatalf("server Addr %q Bound %v, want %q bound", srv.Addr(), srv.Bound(), addr)
		}
		assertServeClosed(t, serveErr)
	})
}

func bootRESTMgmt(t *testing.T) (*app.App, *rest.Server, string, string, string, <-chan error) {
	t.Helper()
	root := repoRoot(t)
	t.Chdir(root)
	token, err := os.ReadFile(filepath.Join(root, "testdata", "secrets", "token-admin"))
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.TrimSpace(string(token))
	addr := freeAddr(t)
	src, err := os.ReadFile(filepath.Join(root, "testdata", "config", "valid", "full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(src), `address: ":8088"`, `address: "`+addr+`"`, 1)
	if text == string(src) {
		t.Fatal("fixture has no management address")
	}
	path := filepath.Join(t.TempDir(), "labsnmp.yaml")
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	svc, err := app.Boot(context.Background(), app.Options{BootstrapPath: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	if got := svc.Active().ManagementAddress; got != addr {
		t.Fatalf("booted management %q, want %q", got, addr)
	}
	srv, err := rest.New(rest.Config{
		Service:    svc,
		RatePerSec: -1,
		Auth:       auth.Static(secret, "admin", model.RoleAdministrator),
		Ready:      func() bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetHTTPRebind(srv.Rebind)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	deadline := time.Now().Add(time.Second)
	for !srv.Bound() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !srv.Bound() {
		t.Fatal("management server did not bind")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return svc, srv, secret, addr, path, serveErr
}

func rewriteMgmt(t *testing.T, path, from, to string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	old := `address: "` + from + `"`
	next := `address: "` + to + `"`
	if to == "" {
		next = `address: ""`
	}
	text := strings.Replace(string(body), old, next, 1)
	if text == string(body) {
		t.Fatalf("management address %q was not rewritten", from)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func postReset(t *testing.T, addr, token string) (int, map[string]any, time.Duration) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/state:reset", strings.NewReader(`{"reason":"ks4"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("reset request after %s: %v", elapsed, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("elapsed %s status %d body %s", elapsed, resp.StatusCode, raw)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode reset body: %v (%s)", err, raw)
	}
	return resp.StatusCode, body, elapsed
}

func assertHealth(t *testing.T, addr string) {
	t.Helper()
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	deadline := time.Now().Add(time.Second)
	var last error
	for {
		resp, err := client.Get("http://" + addr + "/v1/health/live")
		if err == nil {
			raw, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			t.Fatalf("GET %s/v1/health/live status %d body %s", addr, resp.StatusCode, raw)
		}
		last = err
		if time.Now().After(deadline) {
			t.Fatalf("GET %s/v1/health/live: %v", addr, last)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertRefused(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("dial %s connected, want connection refused", addr)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("dial %s: %v, want connection refused", addr, err)
	}
}

func assertServeClosed(t *testing.T, serveErr <-chan error) {
	t.Helper()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve returned %v, want nil (ErrServerClosed)", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the listener closed")
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
