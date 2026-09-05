package app

import (
	"context"
	"strconv"
	"strings"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/mibtree"
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

func (s *App) QueryMap(ctx context.Context, actor Actor, name string, in MapQueryIn) (*MapQueryResult, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	if name == "" {
		return nil, domainerr.ValidationFailed("name is required",
			domainerr.FieldViolation{Path: "name", Code: "required", Message: "name is required"})
	}
	pdu := strings.ToLower(strings.TrimSpace(in.PDU))
	switch pdu {
	case "get", "getnext", "getbulk":
	default:
		return nil, domainerr.ValidationFailed("pdu must be get, getNext, or getBulk",
			domainerr.FieldViolation{Path: "pdu", Code: "invalid_value", Message: "pdu must be get, getNext, or getBulk"})
	}
	if len(in.OIDs) == 0 {
		return nil, domainerr.ValidationFailed("oids is required",
			domainerr.FieldViolation{Path: "oids", Code: "required", Message: "oids is required"})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	tree := snap.Maps[name]
	if tree == nil {
		return nil, domainerr.NotFound("map " + name + " not found")
	}
	oids := make([]mibtree.OID, 0, len(in.OIDs))
	for i, raw := range in.OIDs {
		oid, err := mibtree.ParseOID(raw)
		if err != nil {
			return nil, domainerr.ValidationFailed("invalid oid",
				domainerr.FieldViolation{Path: "oids[" + strconv.Itoa(i) + "]", Code: "invalid_value", Message: err.Error()})
		}
		oids = append(oids, oid)
	}
	var results []mibtree.Result
	switch pdu {
	case "get":
		results = make([]mibtree.Result, len(oids))
		for i, oid := range oids {
			results[i] = tree.Get(oid)
		}
	case "getnext":
		results = make([]mibtree.Result, len(oids))
		for i, oid := range oids {
			results[i] = tree.GetNext(oid)
		}
	case "getbulk":
		results = tree.GetBulk(oids, in.NonRepeaters, in.MaxRepetitions)
	}
	out := &MapQueryResult{Bindings: make([]OIDResult, 0, len(results))}
	for _, res := range results {
		out.Bindings = append(out.Bindings, *s.resultToOID(name, res))
	}
	return out, nil
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
