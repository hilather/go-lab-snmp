package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/hilather/go-lab-snmp/internal/audit"
	"github.com/hilather/go-lab-snmp/internal/compiler"
	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
	"github.com/hilather/go-lab-snmp/internal/store"
)

// Reset rereads the bootstrap mount, compiles, applies trap policy, then
// drops the SET overlay and wipes traps and queries. It swaps only after
// success. A trap-policy failure leaves the ephemeral store and the active
// snapshot unchanged. It never writes the file. CLI listen flags still win
// after Reset.
func (s *App) Reset(ctx context.Context, actor Actor, in ResetIn) (*ApplyResult, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	res, hooks, err := s.resetLocked(ctx, actor, in)
	s.mu.Unlock()
	if err != nil {
		s.observeApply(err)
		return nil, err
	}
	for _, fn := range hooks {
		fn()
	}
	return res, nil
}

func (s *App) resetLocked(ctx context.Context, actor Actor, in ResetIn) (*ApplyResult, []func(), error) {
	prev := s.snaps.Load()
	gen := model.Generation(0)
	if prev != nil {
		gen = prev.Generation + 1
	}

	next, err := s.loadBootstrapCandidate(gen)
	if err != nil {
		return nil, nil, err
	}

	diff, _, err := diffStates(canonicalOf(prev), next.Canonical)
	if err != nil {
		return nil, nil, err
	}

	prevL := s.listenersFor(prev)
	nextL := s.listenersFor(next)
	// An empty YAML address still honors the CLI override, including when prev is nil.
	prevAddr := ""
	if prev != nil {
		prevAddr = prev.ManagementAddress
	}
	oldMgmt := effectiveMgmt(s.mgmtOverride, prevAddr)
	newMgmt := effectiveMgmt(s.mgmtOverride, next.ManagementAddress)

	synced := false
	agentMoved := false
	trapMoved := false
	mgmtMoved := false
	if s.dataPlaneSync != nil {
		if err := s.dataPlaneSync(nextL); err != nil {
			// Sync closes sockets opened in a failed call and leaves the previous bind.
			return nil, nil, asDomain(err)
		}
		synced = true
	} else {
		if s.snmpRebind != nil && nextL.AgentUDP != prevL.AgentUDP {
			if err := s.snmpRebind(nextL.AgentUDP); err != nil {
				return nil, nil, asDomain(err)
			}
			agentMoved = true
		}
		if s.trapRebind != nil && nextL.TrapUDP != prevL.TrapUDP {
			if err := s.trapRebind(nextL.TrapUDP); err != nil {
				return nil, nil, s.rollbackListeners(err, false, agentMoved, false, mgmtMoved, oldMgmt, prevL)
			}
			trapMoved = true
		}
	}
	if s.httpRebind != nil && newMgmt != oldMgmt {
		if err := s.httpRebind(newMgmt); err != nil {
			// A non-nil error means the previous listener is untouched, so
			// management was not moved. Empty newMgmt is the exception: the
			// hook may already have closed the listener and still returned
			// an error. Treat that as moved so rollback rebinds oldMgmt.
			if newMgmt == "" {
				mgmtMoved = true
			}
			return nil, nil, s.rollbackListeners(err, synced, agentMoved, trapMoved, mgmtMoved, oldMgmt, prevL)
		}
		mgmtMoved = true
	}

	if err := s.applyTrapPolicy(next); err != nil {
		return nil, nil, s.rollbackListeners(err, synced, agentMoved, trapMoved, mgmtMoved, oldMgmt, prevL)
	}
	store.ResetEphemeral(s.overlay, s.traps, s.queries)

	displaced := s.snaps.Swap(next)
	s.snaps.SetBootstrap(next)
	s.idemp.clear()
	hooks := append([]func(){}, s.resetHooks...)

	res := &ApplyResult{
		Plan:            *s.planFrom(&candidate{prev: displaced, next: next, diff: diff, warn: warningsOf(next)}),
		Applied:         true,
		Generation:      next.Generation,
		RuntimeRevision: next.Revision,
		StoreGeneration: s.storeGeneration(),
	}
	res.AuditEventID = s.recordAudit(ctx, audit.Event{
		Time:       s.now(),
		ActorID:    actor.ID,
		ActorClass: actor.Class,
		Transport:  actor.Transport,
		Capability: "state.reset",
		Reason:     in.Reason,
		Revision:   next.Revision,
		Previous:   revisionOf(displaced),
		Result:     audit.ResultOK,
		Diff:       toAuditDiff(diff),
	})
	if s.logger != nil {
		s.logger.Log(observability.Record{
			Event:     observability.EventStateReset,
			Component: "app",
			Result:    "ok",
		})
	}
	s.observeApply(nil)
	return cloneApply(res), hooks, nil
}

func (s *App) loadBootstrapCandidate(gen model.Generation) (*snapshot.Snapshot, error) {
	if s.bootstrapPath != "" {
		if _, err := os.Stat(s.bootstrapPath); err != nil {
			if os.IsNotExist(err) {
				return nil, domainerr.ValidationFailed("bootstrap file unavailable",
					domainerr.FieldViolation{Path: "bootstrapPath", Code: "required", Message: "bootstrap file is missing; active snapshot unchanged"})
			}
			return nil, domainerr.Internal("stat bootstrap: " + err.Error())
		}
		st, err := config.LoadFile(s.bootstrapPath)
		if err != nil {
			return nil, asDomain(err)
		}
		snap, err := compiler.Compile(st, compiler.CompileOpts{
			Clock:      s.clock,
			BaseDir:    filepath.Dir(s.bootstrapPath),
			Generation: gen,
		})
		if err != nil {
			return nil, asDomain(err)
		}
		return snap, nil
	}
	boot := s.snaps.Bootstrap()
	if boot == nil || boot.Canonical == nil {
		return nil, domainerr.ValidationFailed("no bootstrap snapshot",
			domainerr.FieldViolation{Path: "bootstrap", Code: "required", Message: "no bootstrap path or snapshot to reset to"})
	}
	copied, err := cloneState(boot.Canonical)
	if err != nil {
		return nil, err
	}
	snap, err := compiler.Compile(copied, compiler.CompileOpts{
		Clock:      s.clock,
		BaseDir:    filepath.Dir(s.bootstrapPath),
		Generation: gen,
	})
	if err != nil {
		return nil, asDomain(err)
	}
	return snap, nil
}

// listenersFor is the desired bind set for snap, including CLI overrides.
// A nil snapshot yields every listener off.
func (s *App) listenersFor(snap *snapshot.Snapshot) DesiredListeners {
	if snap == nil {
		return DesiredListeners{}
	}
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

// rollbackListeners puts sockets back on the snapshot that is still active.
// A hook is undone only when that hook already returned nil. Management is
// undone first, then the data plane. On the fallback path the trap is undone
// before the agent, and a later undo still runs if an earlier undo fails.
// Every failed undo is appended to the returned error.
func (s *App) rollbackListeners(orig error, synced, agentMoved, trapMoved, mgmtMoved bool, oldMgmt string, prev DesiredListeners) error {
	var undos []error
	if mgmtMoved && s.httpRebind != nil {
		if err := s.httpRebind(oldMgmt); err != nil {
			undos = append(undos, err)
		}
	}
	if synced && s.dataPlaneSync != nil {
		if err := s.dataPlaneSync(prev); err != nil {
			undos = append(undos, err)
		}
	}
	if !synced {
		if trapMoved && s.trapRebind != nil {
			if err := s.trapRebind(prev.TrapUDP); err != nil {
				undos = append(undos, err)
			}
		}
		if agentMoved && s.snmpRebind != nil {
			if err := s.snmpRebind(prev.AgentUDP); err != nil {
				undos = append(undos, err)
			}
		}
	}
	if len(undos) == 0 {
		return asDomain(orig)
	}
	parts := make([]string, 0, len(undos))
	for _, err := range undos {
		parts = append(parts, err.Error())
	}
	msg := orig.Error() + "; rollback: " + strings.Join(parts, "; ")
	return asDomain(errors.New(msg))
}

func canonicalOf(s *snapshot.Snapshot) *model.State {
	if s == nil {
		return nil
	}
	return s.Canonical
}

func resolveDTLSCreds(next *snapshot.Snapshot, baseDir string) (cert, key, ca string) {
	if next == nil || !next.DTLSEnabled {
		return "", "", ""
	}
	return resolveMaybe(next.DTLSCertFile, baseDir), resolveMaybe(next.DTLSKeyFile, baseDir), resolveMaybe(next.DTLSClientCAFile, baseDir)
}

func resolveMaybe(path, baseDir string) string {
	if path == "" {
		return ""
	}
	resolved, err := config.ResolveFileRef(path, baseDir)
	if err != nil {
		return path
	}
	return resolved
}
