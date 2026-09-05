package app

import (
	"context"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/store"
)

func (s *App) ListTraps(ctx context.Context, actor Actor, q store.ListQuery) (*TrapList, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	if s.traps == nil {
		return &TrapList{}, nil
	}
	res, err := s.traps.List(q)
	if err != nil {
		return nil, asDomain(err)
	}
	return &TrapList{Items: res.Items, Next: res.Next}, nil
}

func (s *App) GetTrap(ctx context.Context, actor Actor, id string) (*store.TrapRecord, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	if id == "" {
		return nil, domainerr.ValidationFailed("id is required",
			domainerr.FieldViolation{Path: "id", Code: "required", Message: "id is required"})
	}
	if s.traps == nil {
		return nil, domainerr.NotFound("trap " + id + " not found")
	}
	rec, err := s.traps.Get(id)
	if err != nil {
		return nil, asDomain(err)
	}
	return rec, nil
}

func (s *App) GetTrapRaw(ctx context.Context, actor Actor, id string) ([]byte, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	if id == "" {
		return nil, domainerr.ValidationFailed("id is required",
			domainerr.FieldViolation{Path: "id", Code: "required", Message: "id is required"})
	}
	if s.traps == nil {
		return nil, domainerr.NotFound("trap " + id + " not found")
	}
	raw, err := s.traps.Raw(id)
	if err != nil {
		return nil, asDomain(err)
	}
	return raw, nil
}

func (s *App) WaitTraps(ctx context.Context, actor Actor, in TrapWaitIn) (*store.TrapRecord, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	if s.traps == nil {
		return nil, domainerr.Internal("trap store is nil")
	}
	return s.traps.Wait(ctx, in.Filter, in.Timeout)
}

func (s *App) ClearTraps(ctx context.Context, actor Actor) error {
	if err := s.requireCtx(ctx); err != nil {
		return err
	}
	_ = actor
	if s.traps == nil {
		return nil
	}
	s.traps.Clear()
	return nil
}

func (s *App) ListQueries(ctx context.Context, actor Actor) (*QueryList, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	if s.queries == nil {
		return &QueryList{}, nil
	}
	return &QueryList{Items: s.queries.List()}, nil
}
