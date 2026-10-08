package rest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/auth"
	"github.com/hilather/go-lab-snmp/internal/model"
)

// TestDrainAsyncSecondShutdownNoPanic guards the ks4 review crash.
// net/http runs every RegisterOnShutdown hook again on each Shutdown,
// from a goroutine. drainAsync's hook closes a channel; a second
// Shutdown of that same *http.Server must not panic.
//
// The handler stays blocked so the second Shutdown waits in net/http's
// poll loop. That runs the hook before Shutdown returns, so a double
// close crashes this test instead of racing process exit.
func TestDrainAsyncSecondShutdownNoPanic(t *testing.T) {
	srv, release := startHoldServer(t)

	srv.mu.Lock()
	hs := srv.http
	ln := srv.ln
	srv.mu.Unlock()
	if hs == nil || ln == nil {
		t.Fatal("server has no listener")
	}
	srv.drainAsync(hs, ln)

	// Long enough for the onShutdown goroutine to run. The blocked
	// handler keeps Shutdown from returning first.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	err := hs.Shutdown(ctx)
	release()
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Shutdown: %v", err)
	}
}

// TestShutdownWaitsForDetachedDrain is the process-exit grace: after
// Rebind detaches a server, Shutdown waits for that background drain
// and stops when ctx ends.
func TestShutdownWaitsForDetachedDrain(t *testing.T) {
	t.Run("waits for the in-flight request", func(t *testing.T) {
		srv, release := startHoldServer(t)
		if err := srv.Rebind(""); err != nil {
			t.Fatal(err)
		}
		if srv.Bound() {
			t.Fatal("Rebind(\"\") left the listener bound")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- srv.Shutdown(ctx) }()

		select {
		case err := <-done:
			t.Fatalf("Shutdown returned before the request was released: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
		release()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Shutdown did not return after the request finished")
		}
	})

	t.Run("expired context returns promptly", func(t *testing.T) {
		srv, release := startHoldServer(t)
		defer release()
		if err := srv.Rebind(""); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		start := time.Now()
		err := srv.Shutdown(ctx)
		elapsed := time.Since(start)
		if elapsed > time.Second {
			t.Fatalf("Shutdown with an expired context took %s", elapsed)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Shutdown err %v, want context.Canceled", err)
		}
	})
}

// TestRebindShutdownRace overlaps Rebind and Shutdown. The double-close
// panic is unrecovered; -race also covers the drain bookkeeping.
func TestRebindShutdownRace(t *testing.T) {
	srv, _ := newTestServer(t)
	if err := srv.Rebind("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	for i := 0; i < 8; i++ {
		if !srv.Bound() {
			if err := srv.Rebind("127.0.0.1:0"); err != nil {
				t.Fatalf("rebind %d: %v", i, err)
			}
		}
		errCh := make(chan error, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			errCh <- srv.Rebind("")
		}()
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			errCh <- srv.Shutdown(ctx)
		}()
		wg.Wait()
		close(errCh)
		for err := range errCh {
			if err != nil {
				t.Fatalf("iteration %d: %v", i, err)
			}
		}
	}
}

// startHoldServer serves on 127.0.0.1:0 and blocks one authenticated
// GET /hold until release. release is idempotent.
func startHoldServer(t *testing.T) (*Server, func()) {
	t.Helper()
	entered := make(chan struct{})
	letGo := make(chan struct{})
	var enterOnce sync.Once
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(letGo) }) }

	svc := bootTestApp(t)
	srv, err := New(Config{
		Service:    svc,
		RatePerSec: -1,
		Auth:       auth.Static(testToken, "admin", model.RoleAdministrator),
		Ready:      func() bool { return true },
		Mounts: map[string]http.Handler{
			"/hold": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				enterOnce.Do(func() { close(entered) })
				<-letGo
				w.WriteHeader(http.StatusNoContent)
			}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	deadline := time.Now().Add(2 * time.Second)
	for !srv.Bound() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !srv.Bound() {
		t.Fatal("management server did not bind")
	}

	reqErr := make(chan error, 1)
	go func() {
		client := &http.Client{Timeout: 5 * time.Second}
		req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/hold", nil)
		if err != nil {
			reqErr <- err
			return
		}
		req.Header.Set("Authorization", "Bearer "+testToken)
		resp, err := client.Do(req)
		if err != nil {
			reqErr <- err
			return
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			reqErr <- fmt.Errorf("status %d", resp.StatusCode)
			return
		}
		reqErr <- nil
	}()

	select {
	case <-entered:
	case err := <-reqErr:
		t.Fatalf("request ended before the handler blocked: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}

	t.Cleanup(func() {
		release()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		select {
		case <-serveErr:
		case <-time.After(2 * time.Second):
		}
		select {
		case <-reqErr:
		case <-time.After(2 * time.Second):
		}
	})
	return srv, release
}
