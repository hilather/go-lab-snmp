package app

import (
	"context"
	"errors"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
)

// SetOID writes one overlay value. It shares store.Overlay with SNMP SET.
// The body is a single {oid, value}; a missing map/oid is not_found / not_writable.
func (s *App) SetOID(ctx context.Context, actor Actor, in OIDSetIn) (*OIDResult, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	if in.Map == "" {
		return nil, domainerr.ValidationFailed("map is required",
			domainerr.FieldViolation{Path: "map", Code: "required", Message: "map is required"})
	}
	if in.OID == "" {
		return nil, domainerr.ValidationFailed("oid is required",
			domainerr.FieldViolation{Path: "oid", Code: "required", Message: "oids:set body is a single {oid, value}"})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	tree := snap.Maps[in.Map]
	if tree == nil {
		return nil, domainerr.NotFound("map " + in.Map + " not found")
	}
	oid, err := mibtree.ParseOID(in.OID)
	if err != nil {
		return nil, domainerr.ValidationFailed("invalid oid",
			domainerr.FieldViolation{Path: "oid", Code: "invalid_value", Message: err.Error()})
	}
	val := in.Value
	if err := tree.CheckSetCoerce(oid, &val); err != nil {
		return nil, setOIDErr(err)
	}
	s.overlay.Set(in.Map, oid.String(), val)
	got := s.readOIDLocked(in.Map, oid)
	got.Overlay = true
	return got, nil
}

// GetOID evaluates one oid against the compiled tree plus overlay.
func (s *App) GetOID(ctx context.Context, actor Actor, in OIDGetIn) (*OIDResult, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	if in.Map == "" {
		return nil, domainerr.ValidationFailed("map is required",
			domainerr.FieldViolation{Path: "map", Code: "required", Message: "map is required"})
	}
	if in.OID == "" {
		return nil, domainerr.ValidationFailed("oid is required",
			domainerr.FieldViolation{Path: "oid", Code: "required", Message: "oid is required"})
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, err := s.active()
	if err != nil {
		return nil, err
	}
	if snap.Maps[in.Map] == nil {
		return nil, domainerr.NotFound("map " + in.Map + " not found")
	}
	oid, err := mibtree.ParseOID(in.OID)
	if err != nil {
		return nil, domainerr.ValidationFailed("invalid oid",
			domainerr.FieldViolation{Path: "oid", Code: "invalid_value", Message: err.Error()})
	}
	return s.readOIDLocked(in.Map, oid), nil
}

func (s *App) readOIDLocked(mapName string, oid mibtree.OID) *OIDResult {
	live := s.snaps.Load()
	tree := live.Maps[mapName]
	res := tree.Get(oid)
	out := &OIDResult{OID: oid.String(), Exception: res.Exception.String()}
	if res.Exception != mibtree.NoException {
		if res.OID != nil {
			out.OID = res.OID.String()
		}
		return out
	}
	out.OID = res.OID.String()
	if res.Value.ValueFrom == model.ValueFromUptime {
		out.Value = mibtree.Value{Type: model.TypeTimeTicks, Unsigned: uint64(live.UptimeTicks()), ValueFrom: model.ValueFromUptime}
		return out
	}
	if ov, ok := s.overlay.Get(mapName, res.OID.String()); ok {
		out.Value = ov
		out.Overlay = true
		return out
	}
	out.Value = res.Value
	return out
}

func setOIDErr(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, mibtree.ErrNotWritable):
		return domainerr.New(domainerr.CodeNotWritable, err.Error())
	case errors.Is(err, mibtree.ErrWrongType):
		return domainerr.New(domainerr.CodeWrongType, err.Error())
	default:
		return domainerr.ValidationFailed(err.Error(),
			domainerr.FieldViolation{Path: "value", Code: "invalid_value", Message: err.Error()})
	}
}
