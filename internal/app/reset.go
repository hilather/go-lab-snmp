package app

import (
	"context"
	"os"
	"path/filepath"

	"github.com/hilather/go-lab-snmp/internal/audit"
	"github.com/hilather/go-lab-snmp/internal/compiler"
	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
	"github.com/hilather/go-lab-snmp/internal/store"
)

// Reset rereads the bootstrap mount, compiles, drops the SET overlay, wipes
// traps and queries, and swaps only after success. It never writes the file.
// CLI listen flags still win after Reset.
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

	oldSNMP, oldTrap, oldMgmt := "", "", ""
	if prev != nil {
		oldSNMP = effectiveSNMP(s.snmpOverride, prev.AgentAddress, prev.AgentEnabled)
		oldTrap = effectiveTrap(s.trapOverride, prev.TrapAddress, prev.TrapsEnabled)
		oldMgmt = effectiveMgmt(s.mgmtOverride, prev.ManagementAddress)
	}
	newSNMP := effectiveSNMP(s.snmpOverride, next.AgentAddress, next.AgentEnabled)
	newTrap := effectiveTrap(s.trapOverride, next.TrapAddress, next.TrapsEnabled)
	newMgmt := effectiveMgmt(s.mgmtOverride, next.ManagementAddress)

	cert, key, ca := resolveDTLSCreds(next, filepath.Dir(s.bootstrapPath))
	desired := DesiredListeners{
		AgentUDP:         newSNMP,
		TrapUDP:          newTrap,
		AgentTCP:         effectiveTCP(next.TCPEnabled, next.TCPAddress, newSNMP),
		TrapTCP:          effectiveTCP(next.TCPEnabled, next.TCPTrapsAddress, newTrap),
		AgentDTLS:        effectiveDTLS(s.dtlsOverride, next.DTLSAddress, next.DTLSEnabled),
		TrapDTLS:         effectiveDTLS(s.dtlsTrapOverride, next.DTLSTrapsAddress, next.DTLSEnabled),
		DTLSCertFile:     cert,
		DTLSKeyFile:      key,
		DTLSClientCAFile: ca,
	}
	if s.dataPlaneSync != nil {
		if err := s.dataPlaneSync(desired); err != nil {
			return nil, nil, asDomain(err)
		}
	} else {
		if s.snmpRebind != nil && newSNMP != oldSNMP {
			if err := s.snmpRebind(newSNMP); err != nil {
				return nil, nil, asDomain(err)
			}
		}
		if s.trapRebind != nil && newTrap != oldTrap {
			if err := s.trapRebind(newTrap); err != nil {
				return nil, nil, asDomain(err)
			}
		}
	}
	if s.httpRebind != nil && newMgmt != oldMgmt {
		if err := s.httpRebind(newMgmt); err != nil {
			return nil, nil, asDomain(err)
		}
	}

	store.ResetEphemeral(s.overlay, s.traps, s.queries)
	if err := s.applyTrapPolicy(next); err != nil {
		return nil, nil, err
	}

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
