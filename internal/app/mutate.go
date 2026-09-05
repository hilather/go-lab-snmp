package app

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/hilather/go-lab-snmp/internal/compiler"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
	"github.com/hilather/go-lab-snmp/internal/store"
	"github.com/hilather/go-lab-snmp/internal/testutil"
)

type candidate struct {
	prev *snapshot.Snapshot
	next *snapshot.Snapshot
	ops  []model.Operation
	diff []DiffEntry
	warn []Warning
}

// Plan dry-runs the mutation pipeline. expectedRevision is required.
func (s *App) Plan(ctx context.Context, actor Actor, in ChangeIn) (*Plan, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.planLocked(in)
}

func (s *App) planLocked(in ChangeIn) (*Plan, error) {
	fp, err := fingerprintChange(in)
	if err != nil {
		return nil, err
	}
	if hit, err := s.idemp.lookup(in.IdempotencyKey, fp); err != nil {
		return nil, err
	} else if hit != nil {
		if hit.plan != nil {
			return clonePlan(hit.plan), nil
		}
		if hit.apply != nil {
			return clonePlan(&hit.apply.Plan), nil
		}
	}
	cand, err := s.buildCandidate(in, true)
	if err != nil {
		s.forgetIdempOnConflict(in.IdempotencyKey, err)
		return nil, err
	}
	p := s.planFrom(cand)
	s.idemp.storePlan(in.IdempotencyKey, fp, p)
	return clonePlan(p), nil
}

// Apply compiles the candidate and atomically swaps only after success.
func (s *App) Apply(ctx context.Context, actor Actor, in ChangeIn) (*ApplyResult, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	res, hooks, err := s.applyLocked(ctx, actor, in)
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

func (s *App) applyLocked(ctx context.Context, actor Actor, in ChangeIn) (*ApplyResult, []func(), error) {
	_ = ctx
	_ = actor
	if strings.TrimSpace(in.IdempotencyKey) == "" {
		return nil, nil, domainerr.ValidationFailed("Idempotency-Key is required",
			domainerr.FieldViolation{Path: "idempotencyKey", Code: "required", Message: "Idempotency-Key is required for apply"})
	}
	fp, err := fingerprintChange(in)
	if err != nil {
		return nil, nil, err
	}
	if hit, err := s.idemp.lookup(in.IdempotencyKey, fp); err != nil {
		return nil, nil, err
	} else if hit != nil && hit.apply != nil {
		return cloneApply(hit.apply), nil, nil
	}
	cand, err := s.buildCandidate(in, true)
	if err != nil {
		s.forgetIdempOnConflict(in.IdempotencyKey, err)
		return nil, nil, err
	}
	if err := s.syncTrapPolicyIfChanged(cand.prev, cand.next); err != nil {
		return nil, nil, err
	}
	_ = s.snaps.Swap(cand.next)
	res := &ApplyResult{
		Plan:            *s.planFrom(cand),
		Applied:         true,
		Generation:      cand.next.Generation,
		RuntimeRevision: cand.next.Revision,
		StoreGeneration: s.storeGeneration(),
	}
	s.idemp.storeApply(in.IdempotencyKey, fp, res)
	if s.logger != nil {
		s.logger.Log(observability.Record{
			Event:     observability.EventStateApply,
			Component: "app",
			Result:    "ok",
		})
	}
	s.observeApply(nil)
	return cloneApply(res), append([]func(){}, s.applyHooks...), nil
}

// Validate inspects a candidate document and/or operations. It never swaps
// and does not require expectedRevision.
func (s *App) Validate(ctx context.Context, actor Actor, in ValidateIn) (*Plan, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	s.mu.Lock()
	defer s.mu.Unlock()
	var prev *snapshot.Snapshot
	var base *model.State
	if in.State != nil {
		copied, err := cloneState(in.State)
		if err != nil {
			return nil, err
		}
		base = copied
		prev = s.snaps.Load()
	} else {
		snap, err := s.active()
		if err != nil {
			return nil, err
		}
		prev = snap
		copied, err := cloneState(snap.Canonical)
		if err != nil {
			return nil, err
		}
		base = copied
	}
	if err := applyOperations(base, in.Operations); err != nil {
		return nil, err
	}
	next, err := s.compileCandidate(base, prev)
	if err != nil {
		return nil, asDomain(err)
	}
	beforeState := in.State
	if prev != nil {
		beforeState = prev.Canonical
	}
	diff, _, err := diffStates(beforeState, next.Canonical)
	if err != nil {
		return nil, err
	}
	return clonePlan(s.planFrom(&candidate{
		prev: prev,
		next: next,
		ops:  append([]model.Operation(nil), in.Operations...),
		diff: diff,
		warn: warningsOf(next),
	})), nil
}

func (s *App) buildCandidate(in ChangeIn, requireRev bool) (*candidate, error) {
	prev, err := s.active()
	if err != nil {
		return nil, err
	}
	if requireRev {
		if in.ExpectedRevision == "" {
			return nil, domainerr.ValidationFailed("expectedRevision is required",
				domainerr.FieldViolation{Path: "expectedRevision", Code: "required", Message: "expectedRevision is required for plan and apply"})
		}
		if in.ExpectedRevision != prev.Revision {
			return nil, domainerr.RevisionMismatch("active revision does not match expectedRevision", string(prev.Revision)).
				WithRemediation("Re-read GET state and re-plan against the current revision.")
		}
	}
	copied, err := cloneState(prev.Canonical)
	if err != nil {
		return nil, err
	}
	if err := applyOperations(copied, in.Operations); err != nil {
		return nil, err
	}
	if err := rejectResetOnly(prev.Canonical, copied); err != nil {
		return nil, err
	}
	next, err := s.compileCandidate(copied, prev)
	if err != nil {
		return nil, asDomain(err)
	}
	diff, _, err := diffStates(prev.Canonical, next.Canonical)
	if err != nil {
		return nil, err
	}
	return &candidate{
		prev: prev,
		next: next,
		ops:  append([]model.Operation(nil), in.Operations...),
		diff: diff,
		warn: warningsOf(next),
	}, nil
}

func (s *App) compileCandidate(st *model.State, prev *snapshot.Snapshot) (*snapshot.Snapshot, error) {
	gen := model.Generation(1)
	boot := model.Revision("")
	if prev != nil {
		gen = prev.Generation + 1
		boot = prev.BootstrapRevision
	}
	var tclk testutil.Clock
	if s != nil {
		tclk = s.clock
	}
	baseDir := ""
	if s != nil {
		baseDir = filepath.Dir(s.bootstrapPath)
	}
	return compiler.Compile(st, compiler.CompileOpts{
		Clock:             tclk,
		BaseDir:           baseDir,
		Generation:        gen,
		BootstrapRevision: boot,
		Previous:          prev,
	})
}

func (s *App) planFrom(c *candidate) *Plan {
	prevRev := model.Revision("")
	if c.prev != nil {
		prevRev = c.prev.Revision
	}
	return &Plan{
		PreviousRevision:  prevRev,
		CandidateRevision: c.next.Revision,
		Drifted:           c.next.Drifted(),
		Diff:              c.diff,
		Warnings:          c.warn,
		Operations:        append([]model.Operation(nil), c.ops...),
	}
}

func (s *App) forgetIdempOnConflict(key string, err error) {
	de, ok := domainerr.As(err)
	if !ok || (de.Code != domainerr.CodeRevisionMismatch && de.Code != domainerr.CodeRevisionConflict) {
		return
	}
	if s.idemp.hasApply(key) {
		return
	}
	s.idemp.evict(key)
}

func (s *App) syncTrapPolicyIfChanged(prev, next *snapshot.Snapshot) error {
	if s.traps == nil || next == nil || next.Canonical == nil {
		return nil
	}
	if prev != nil && prev.Canonical != nil && jsonEqual(prev.Canonical.Spec.Traps, next.Canonical.Spec.Traps) {
		return nil
	}
	return s.applyTrapPolicy(next)
}

func (s *App) applyTrapPolicy(next *snapshot.Snapshot) error {
	if s.traps == nil || next == nil || next.Canonical == nil {
		return nil
	}
	tp := next.Canonical.Spec.Traps
	if err := s.traps.ReplaceCaps(store.TrapPolicy{
		MaxMessages: tp.MaxMessages,
		MaxBytes:    tp.MaxBytes,
		FullPolicy:  tp.FullPolicy,
		MaxWait:     tp.MaxWait,
	}); err != nil {
		return asDomain(err)
	}
	return nil
}

func (s *App) storeGeneration() uint64 {
	if s == nil || s.overlay == nil {
		return 0
	}
	return s.overlay.Generation()
}

func (s *App) observeApply(err error) {
	if s == nil || s.metrics == nil {
		return
	}
	result := "ok"
	if err != nil {
		result = "error"
		if de, ok := domainerr.As(err); ok && de.Code == domainerr.CodeRevisionConflict {
			result = "conflict"
		}
	}
	s.metrics.Inc(observability.MetricApplyTotal, map[string]string{"result": observability.ApplyResult(result)}, 1)
}

func warningsOf(snap *snapshot.Snapshot) []Warning {
	if snap == nil {
		return nil
	}
	var out []Warning
	for _, w := range snap.Warnings {
		out = append(out, Warning{Code: w.Code, Message: w.Message})
	}
	return out
}

func cloneState(st *model.State) (*model.State, error) {
	if st == nil {
		return nil, domainerr.Internal("nil state")
	}
	b, err := json.Marshal(st)
	if err != nil {
		return nil, domainerr.Internal("clone: " + err.Error())
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out model.State
	if err := dec.Decode(&out); err != nil {
		return nil, domainerr.Internal("clone: " + err.Error())
	}
	return &out, nil
}
