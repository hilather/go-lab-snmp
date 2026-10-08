package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// activeListeners is the data-plane bind set of the snapshot that is still
// active, including TCP, DTLS, CLI overrides, and resolved DTLS paths.
// It does not call listenersFor; the formula is what Reset must roll back to.
func activeListeners(s *App) DesiredListeners {
	snap := s.Active()
	agentUDP := effectiveSNMP(s.snmpOverride, snap.AgentAddress, snap.AgentEnabled)
	trapUDP := effectiveTrap(s.trapOverride, snap.TrapAddress, snap.TrapsEnabled)
	cert, key, ca := resolveDTLSCreds(snap, filepath.Dir(s.bootstrapPath))
	return DesiredListeners{
		AgentUDP:         agentUDP,
		TrapUDP:          trapUDP,
		AgentTCP:         effectiveTCP(snap.TCPEnabled, snap.TCPAddress, agentUDP),
		TrapTCP:          effectiveTCP(snap.TCPEnabled, snap.TCPTrapsAddress, trapUDP),
		AgentDTLS:        effectiveDTLS(s.dtlsOverride, snap.DTLSAddress, snap.DTLSEnabled),
		TrapDTLS:         effectiveDTLS(s.dtlsTrapOverride, snap.DTLSTrapsAddress, snap.DTLSEnabled),
		DTLSCertFile:     cert,
		DTLSKeyFile:      key,
		DTLSClientCAFile: ca,
	}
}

func insertManagement(t *testing.T, path, addr, anchor string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	needle := "\n    " + anchor + ":\n"
	insert := "\n    management:\n      address: \"" + addr + "\"\n    " + anchor + ":\n"
	next := strings.Replace(string(body), needle, insert, 1)
	if next == string(body) {
		t.Fatalf("fixture has no %s listener to anchor management", anchor)
	}
	if err := os.WriteFile(path, []byte(next), 0o644); err != nil {
		t.Fatal(err)
	}
}

func rewriteFixture(t *testing.T, path string, pairs ...string) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs)%2 != 0 {
		t.Fatal("rewrite pairs")
	}
	text := string(body)
	for i := 0; i < len(pairs); i += 2 {
		next := strings.Replace(text, pairs[i], pairs[i+1], 1)
		if next == text {
			t.Fatalf("fixture text %q was not rewritten", pairs[i])
		}
		text = next
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func bootPath(t *testing.T, path string) *App {
	t.Helper()
	svc, err := Boot(context.Background(), Options{BootstrapPath: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	return svc
}

// TestFailedResetRollsBackDataPlane asserts that a reset whose management
// rebind fails does not leave the data-plane hook's commit in place.
// Production Sync swaps sockets before it returns; a later error must
// roll that commit back to the listeners of the still-active snapshot.
func TestFailedResetRollsBackDataPlane(t *testing.T) {
	t.Run("udp", func(t *testing.T) {
		path := copyFull(t)
		assertRollbackSync(t, path,
			`address: ":161"`, `address: "127.0.0.1:1161"`,
			`address: ":8088"`, `address: "127.0.0.1:18088"`,
		)
	})
	t.Run("tcp", func(t *testing.T) {
		path := copyNamed(t, "tcp-enabled.yaml")
		insertManagement(t, path, "127.0.0.1:18088", "tcp")
		assertRollbackSync(t, path,
			`address: ":1161"`, `address: "127.0.0.1:2161"`,
			`address: "127.0.0.1:18088"`, `address: "127.0.0.1:19088"`,
		)
	})
	t.Run("dtls", func(t *testing.T) {
		path := copyNamed(t, "dtls-enabled.yaml")
		insertManagement(t, path, "127.0.0.1:18088", "dtls")
		assertRollbackSync(t, path,
			`address: ":161"`, `address: "127.0.0.1:1161"`,
			`address: "127.0.0.1:18088"`, `address: "127.0.0.1:19088"`,
		)
	})
}

func assertRollbackSync(t *testing.T, path string, pairs ...string) {
	t.Helper()
	svc := bootPath(t, path)
	oldRev := svc.Active().Revision
	rewriteFixture(t, path, pairs...)

	var calls []DesiredListeners
	svc.SetDataPlaneSync(func(desired DesiredListeners) error {
		calls = append(calls, desired)
		return nil
	})
	svc.SetHTTPRebind(func(string) error {
		return errors.New("management bind failed")
	})

	_, err := svc.Reset(context.Background(), actor(), ResetIn{Reason: "partial"})
	if err == nil {
		t.Fatal("expected management bind error")
	}
	if svc.Active().Revision != oldRev {
		t.Fatal("failed reset swapped the snapshot")
	}
	want := activeListeners(svc)
	switch {
	case svc.Active().TCPEnabled && (want.AgentTCP == "" || want.TrapTCP == ""):
		t.Fatalf("tcp rollback value dropped inherited listeners: %+v", want)
	case svc.Active().DTLSEnabled && (want.AgentDTLS == "" || want.TrapDTLS == "" || want.DTLSCertFile == ""):
		t.Fatalf("dtls rollback value dropped inherited listeners: %+v", want)
	}
	if len(calls) == 0 {
		t.Fatal("data plane sync was not called")
	}
	got := calls[len(calls)-1]
	if got != want {
		t.Fatalf("failed reset left data plane on %+v, want %+v", got, want)
	}
}

// TestFailedTrapRebindRollsBackAgent asserts the fallback hooks undo an
// agent rebind when the trap rebind fails.
func TestFailedTrapRebindRollsBackAgent(t *testing.T) {
	path := copyFull(t)
	svc := bootPath(t, path)
	oldAgent := svc.Active().AgentAddress
	oldRev := svc.Active().Revision
	rewriteFixture(t, path,
		`address: ":161"`, `address: "127.0.0.1:1161"`,
		`address: ":162"`, `address: "127.0.0.1:1162"`,
	)

	var addrs []string
	svc.SetSNMPRebind(func(addr string) error {
		addrs = append(addrs, addr)
		return nil
	})
	svc.SetTrapRebind(func(string) error {
		return errors.New("trap bind failed")
	})

	_, err := svc.Reset(context.Background(), actor(), ResetIn{Reason: "trap-partial"})
	if err == nil {
		t.Fatal("expected trap bind error")
	}
	if svc.Active().Revision != oldRev {
		t.Fatal("failed reset swapped the snapshot")
	}
	if len(addrs) == 0 || addrs[len(addrs)-1] != oldAgent {
		t.Fatalf("last agent address %v, want %q", addrs, oldAgent)
	}
}

type rebindCall struct {
	kind string
	addr string
}

// TestFailedHTTPRebindRollsBackTrapAndAgent asserts fallback undo runs only
// for hooks that already returned nil, trap first, then agent.
func TestFailedHTTPRebindRollsBackTrapAndAgent(t *testing.T) {
	t.Run("agent-trap-management", func(t *testing.T) {
		path := copyFull(t)
		svc := bootPath(t, path)
		oldAgent := svc.Active().AgentAddress
		oldTrap := svc.Active().TrapAddress
		oldRev := svc.Active().Revision
		rewriteFixture(t, path,
			`address: ":161"`, `address: "127.0.0.1:1161"`,
			`address: ":162"`, `address: "127.0.0.1:1162"`,
			`address: ":8088"`, `address: "127.0.0.1:18088"`,
		)
		var calls []rebindCall
		svc.SetSNMPRebind(func(addr string) error {
			calls = append(calls, rebindCall{"snmp", addr})
			return nil
		})
		svc.SetTrapRebind(func(addr string) error {
			calls = append(calls, rebindCall{"trap", addr})
			return nil
		})
		svc.SetHTTPRebind(func(string) error {
			return errors.New("management bind failed")
		})
		_, err := svc.Reset(context.Background(), actor(), ResetIn{Reason: "http-partial"})
		if err == nil {
			t.Fatal("expected management bind error")
		}
		if svc.Active().Revision != oldRev {
			t.Fatal("failed reset swapped the snapshot")
		}
		want := []rebindCall{
			{"snmp", "127.0.0.1:1161"},
			{"trap", "127.0.0.1:1162"},
			{"trap", oldTrap},
			{"snmp", oldAgent},
		}
		if len(calls) != len(want) {
			t.Fatalf("rebinds %v want %v", calls, want)
		}
		for i := range want {
			if calls[i] != want[i] {
				t.Fatalf("rebinds %v want %v", calls, want)
			}
		}
	})

	t.Run("agent-management-only", func(t *testing.T) {
		path := copyFull(t)
		svc := bootPath(t, path)
		oldAgent := svc.Active().AgentAddress
		oldRev := svc.Active().Revision
		rewriteFixture(t, path,
			`address: ":161"`, `address: "127.0.0.1:1161"`,
			`address: ":8088"`, `address: "127.0.0.1:18088"`,
		)
		var snmp []string
		svc.SetSNMPRebind(func(addr string) error {
			snmp = append(snmp, addr)
			return nil
		})
		svc.SetTrapRebind(func(addr string) error {
			t.Errorf("trapRebind(%s) called", addr)
			return nil
		})
		svc.SetHTTPRebind(func(string) error {
			return errors.New("management bind failed")
		})
		_, err := svc.Reset(context.Background(), actor(), ResetIn{Reason: "http-agent"})
		if err == nil {
			t.Fatal("expected management bind error")
		}
		if svc.Active().Revision != oldRev {
			t.Fatal("failed reset swapped the snapshot")
		}
		oldN := 0
		for _, addr := range snmp {
			if addr == oldAgent {
				oldN++
			}
		}
		if oldN != 1 || len(snmp) != 2 {
			t.Fatalf("snmpRebind calls %v, want the new address then %q once", snmp, oldAgent)
		}
	})
}

// TestFailedRebindRollbackErrorStillUndoesAgent asserts a failing trap undo
// still undoes the agent, and the error carries the original failure plus
// every failed undo.
func TestFailedRebindRollbackErrorStillUndoesAgent(t *testing.T) {
	path := copyFull(t)
	svc := bootPath(t, path)
	oldAgent := svc.Active().AgentAddress
	oldTrap := svc.Active().TrapAddress
	oldRev := svc.Active().Revision
	rewriteFixture(t, path,
		`address: ":161"`, `address: "127.0.0.1:1161"`,
		`address: ":162"`, `address: "127.0.0.1:1162"`,
		`address: ":8088"`, `address: "127.0.0.1:18088"`,
	)
	agentUndo := 0
	trapUndo := 0
	svc.SetSNMPRebind(func(addr string) error {
		if addr == oldAgent {
			agentUndo++
			return errors.New("agent rollback failed")
		}
		return nil
	})
	svc.SetTrapRebind(func(addr string) error {
		if addr == oldTrap {
			trapUndo++
			return errors.New("trap rollback failed")
		}
		return nil
	})
	svc.SetHTTPRebind(func(string) error {
		return errors.New("management bind failed")
	})
	_, err := svc.Reset(context.Background(), actor(), ResetIn{Reason: "rollback-error"})
	if err == nil {
		t.Fatal("expected management bind error")
	}
	if svc.Active().Revision != oldRev {
		t.Fatal("failed reset swapped the snapshot")
	}
	if trapUndo != 1 {
		t.Fatalf("trap undo ran %d times", trapUndo)
	}
	if agentUndo != 1 {
		t.Fatalf("agent undo ran %d times", agentUndo)
	}
	msg := err.Error()
	const want = "management bind failed; rollback: trap rollback failed; agent rollback failed"
	if !strings.Contains(msg, want) {
		t.Fatalf("error %q missing %q", msg, want)
	}
}
