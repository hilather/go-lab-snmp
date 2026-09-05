package snmpagent

import (
	"errors"

	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
	"github.com/hilather/go-lab-snmp/internal/store"
)

func (rt *Runtime) servePDU(ver snmpwire.Version, access, mapName string, req snmpwire.PDU) snmpwire.PDU {
	resp := snmpwire.PDU{
		Type:      snmpwire.PDUResponse,
		RequestID: req.RequestID,
	}
	if rt == nil || rt.Maps[mapName] == nil {
		resp.ErrorStatus = snmpwire.ErrorStatusGenErr
		resp.VarBinds = copyBinds(req.VarBinds)
		return resp
	}
	if req.Type != snmpwire.PDUGetBulk && rt.MaxVarBinds > 0 && len(req.VarBinds) > rt.MaxVarBinds {
		resp.ErrorStatus = snmpwire.ErrorStatusTooBig
		return resp
	}
	switch req.Type {
	case snmpwire.PDUGet:
		return rt.serveGet(ver, mapName, req)
	case snmpwire.PDUGetNext:
		return rt.serveGetNext(ver, mapName, req)
	case snmpwire.PDUGetBulk:
		return rt.serveGetBulk(mapName, req)
	case snmpwire.PDUSet:
		return rt.serveSet(ver, access, mapName, req)
	default:
		resp.ErrorStatus = snmpwire.ErrorStatusGenErr
		resp.VarBinds = copyBinds(req.VarBinds)
		return resp
	}
}

func (rt *Runtime) serveGet(ver snmpwire.Version, mapName string, req snmpwire.PDU) snmpwire.PDU {
	resp := snmpwire.PDU{Type: snmpwire.PDUResponse, RequestID: req.RequestID}
	vbs := make([]snmpwire.VarBind, len(req.VarBinds))
	for i, vb := range req.VarBinds {
		res := rt.get(mapName, toMIBOID(vb.Name))
		if ver == snmpwire.VersionV1 && res.Exception != mibtree.NoException {
			resp.ErrorStatus = snmpwire.ErrorStatusNoSuchName
			resp.ErrorIndex = int32(i + 1)
			resp.VarBinds = copyBinds(req.VarBinds)
			return resp
		}
		if res.Exception != mibtree.NoException {
			vbs[i] = snmpwire.VarBind{Name: append(snmpwire.OID(nil), vb.Name...), Value: exceptionValue(res.Exception)}
			continue
		}
		vbs[i] = resultBind(res)
	}
	resp.VarBinds = vbs
	return resp
}

func (rt *Runtime) serveGetNext(ver snmpwire.Version, mapName string, req snmpwire.PDU) snmpwire.PDU {
	resp := snmpwire.PDU{Type: snmpwire.PDUResponse, RequestID: req.RequestID}
	vbs := make([]snmpwire.VarBind, len(req.VarBinds))
	for i, vb := range req.VarBinds {
		res := rt.getNext(mapName, toMIBOID(vb.Name))
		if ver == snmpwire.VersionV1 && res.Exception != mibtree.NoException {
			resp.ErrorStatus = snmpwire.ErrorStatusNoSuchName
			resp.ErrorIndex = int32(i + 1)
			resp.VarBinds = copyBinds(req.VarBinds)
			return resp
		}
		if res.Exception != mibtree.NoException {
			vbs[i] = snmpwire.VarBind{Name: append(snmpwire.OID(nil), vb.Name...), Value: exceptionValue(res.Exception)}
			continue
		}
		vbs[i] = resultBind(res)
	}
	resp.VarBinds = vbs
	return resp
}

func (rt *Runtime) serveGetBulk(mapName string, req snmpwire.PDU) snmpwire.PDU {
	resp := snmpwire.PDU{Type: snmpwire.PDUResponse, RequestID: req.RequestID}
	oids := make([]mibtree.OID, len(req.VarBinds))
	for i, vb := range req.VarBinds {
		oids[i] = toMIBOID(vb.Name)
	}
	tree := rt.Maps[mapName]
	results := tree.GetBulk(oids, int(req.NonRepeaters), int(req.MaxRepetitions))
	if rt.MaxVarBinds > 0 && len(results) > rt.MaxVarBinds {
		results = results[:rt.MaxVarBinds]
	}
	vbs := make([]snmpwire.VarBind, len(results))
	for i, res := range results {
		if res.Exception == mibtree.NoException {
			res = rt.get(mapName, res.OID)
		}
		if res.Exception != mibtree.NoException {
			vbs[i] = snmpwire.VarBind{Name: toWireOID(res.OID), Value: exceptionValue(res.Exception)}
			continue
		}
		vbs[i] = resultBind(res)
	}
	resp.VarBinds = vbs
	return resp
}

func (rt *Runtime) serveSet(ver snmpwire.Version, access, mapName string, req snmpwire.PDU) snmpwire.PDU {
	resp := snmpwire.PDU{
		Type:      snmpwire.PDUResponse,
		RequestID: req.RequestID,
		VarBinds:  copyBinds(req.VarBinds),
	}
	if access != model.AccessReadWrite {
		resp.ErrorStatus = setAccessStatus(ver)
		if len(req.VarBinds) > 0 {
			resp.ErrorIndex = 1
		}
		return resp
	}
	tree := rt.Maps[mapName]
	pairs := make([]store.Pair, 0, len(req.VarBinds))
	for i, vb := range req.VarBinds {
		oid := toMIBOID(vb.Name)
		val := fromWireValue(vb.Value)
		if err := checkSetCoerce(tree, oid, &val); err != nil {
			resp.ErrorStatus = setErrorStatus(ver, err)
			resp.ErrorIndex = int32(i + 1)
			return resp
		}
		pairs = append(pairs, store.Pair{OID: oid.String(), Value: val})
	}
	if len(pairs) > 0 {
		rt.Overlay.SetAll(mapName, pairs)
	}
	return resp
}

func checkSetCoerce(tree *mibtree.Tree, oid mibtree.OID, val *mibtree.Value) error {
	if val == nil {
		return mibtree.ErrWrongType
	}
	err := tree.CheckSet(oid, *val)
	if err == nil {
		return nil
	}
	if !errors.Is(err, mibtree.ErrWrongType) {
		return err
	}
	switch val.Type {
	case model.TypeGauge32:
		val.Type = model.TypeUnsigned32
		return tree.CheckSet(oid, *val)
	case model.TypeUnsigned32:
		val.Type = model.TypeGauge32
		return tree.CheckSet(oid, *val)
	default:
		return err
	}
}

func setAccessStatus(ver snmpwire.Version) int32 {
	if ver == snmpwire.VersionV1 {
		return snmpwire.ErrorStatusNoSuchName
	}
	return snmpwire.ErrorStatusNoAccess
}

func setErrorStatus(ver snmpwire.Version, err error) int32 {
	if ver == snmpwire.VersionV1 {
		switch {
		case errors.Is(err, mibtree.ErrNotWritable):
			return snmpwire.ErrorStatusNoSuchName
		case errors.Is(err, mibtree.ErrWrongType), errors.Is(err, mibtree.ErrWrongLength), errors.Is(err, mibtree.ErrWrongValue):
			return snmpwire.ErrorStatusBadValue
		default:
			return snmpwire.ErrorStatusGenErr
		}
	}
	switch {
	case errors.Is(err, mibtree.ErrNotWritable):
		return snmpwire.ErrorStatusNotWritable
	case errors.Is(err, mibtree.ErrWrongType):
		return snmpwire.ErrorStatusWrongType
	case errors.Is(err, mibtree.ErrWrongLength):
		return snmpwire.ErrorStatusWrongLength
	case errors.Is(err, mibtree.ErrWrongValue):
		return snmpwire.ErrorStatusWrongValue
	default:
		return snmpwire.ErrorStatusGenErr
	}
}

func copyBinds(vbs []snmpwire.VarBind) []snmpwire.VarBind {
	if vbs == nil {
		return nil
	}
	out := make([]snmpwire.VarBind, len(vbs))
	for i := range vbs {
		out[i] = snmpwire.VarBind{
			Name:  append(snmpwire.OID(nil), vbs[i].Name...),
			Value: vbs[i].Value,
		}
	}
	return out
}
