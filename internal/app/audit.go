package app

import (
	"context"

	"github.com/hilather/go-lab-snmp/internal/audit"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
)

// Audit returns the process ring so adapters can share it as a Sink.
func (s *App) Audit() *audit.Fanout {
	if s == nil {
		return nil
	}
	return s.audit
}

func (s *App) recordAudit(ctx context.Context, ev audit.Event) string {
	if s == nil || s.audit == nil {
		return ""
	}
	if ev.Result == "" {
		ev.Result = audit.ResultOK
	}
	return s.audit.Record(ctx, ev).ID
}

func (s *App) QueryAudit(ctx context.Context, actor Actor, in AuditQuery) (*AuditList, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	if s.audit == nil {
		return &AuditList{Events: []AuditEvent{}}, nil
	}
	return &AuditList{Events: s.audit.List(in.Limit)}, nil
}

func (s *App) GetAudit(ctx context.Context, actor Actor, id string) (*AuditEvent, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	if id == "" {
		return nil, domainerr.ValidationFailed("id is required",
			domainerr.FieldViolation{Path: "id", Code: "required", Message: "id is required"})
	}
	if s.audit == nil {
		return nil, domainerr.NotFound("audit event " + id + " not found")
	}
	ev, ok := s.audit.Get(id)
	if !ok {
		return nil, domainerr.NotFound("audit event " + id + " not found")
	}
	return &ev, nil
}

func revisionOf(s *snapshot.Snapshot) model.Revision {
	if s == nil {
		return ""
	}
	return s.Revision
}

func toAuditDiff(in []DiffEntry) []audit.RedactedEntry {
	if len(in) == 0 {
		return nil
	}
	out := make([]audit.RedactedEntry, len(in))
	for i, d := range in {
		out[i] = audit.RedactedEntry{Path: d.Path, Op: d.Op, Before: d.Before, After: d.After}
	}
	return out
}
