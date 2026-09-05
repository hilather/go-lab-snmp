package app

import (
	"context"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func (s *App) ListMaps(ctx context.Context, actor Actor) (*MapList, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	copied, err := cloneState(snap.Canonical)
	if err != nil {
		return nil, err
	}
	return &MapList{Items: append([]model.MapSpec(nil), copied.Spec.Maps...)}, nil
}

func (s *App) GetMap(ctx context.Context, actor Actor, name string) (*model.MapSpec, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	if name == "" {
		return nil, domainerr.ValidationFailed("name is required",
			domainerr.FieldViolation{Path: "name", Code: "required", Message: "name is required"})
	}
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	copied, err := cloneState(snap.Canonical)
	if err != nil {
		return nil, err
	}
	for i := range copied.Spec.Maps {
		if copied.Spec.Maps[i].Name == name {
			out := copied.Spec.Maps[i]
			return &out, nil
		}
	}
	return nil, domainerr.NotFound("map " + name + " not found")
}

func (s *App) ListCommunities(ctx context.Context, actor Actor) (*CommunityList, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	copied, err := cloneState(snap.Canonical)
	if err != nil {
		return nil, err
	}
	return &CommunityList{Items: append([]model.CommunitySpec(nil), copied.Spec.Communities...)}, nil
}

func (s *App) ListUsers(ctx context.Context, actor Actor) (*UserList, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	copied, err := cloneState(snap.Canonical)
	if err != nil {
		return nil, err
	}
	return &UserList{Items: append([]model.UserSpec(nil), copied.Spec.Users...)}, nil
}
