package snmpwire

import (
	"bytes"
	"fmt"
)

func decodePDU(tag byte, content []byte) (*PDU, error) {
	if tag&0xa0 != 0xa0 || tag&0x1f > 8 {
		return nil, fmt.Errorf("snmpwire: unknown PDU tag 0x%02x: %w", tag, ErrPDU)
	}
	if tag&0x20 == 0 {
		return nil, fmt.Errorf("snmpwire: PDU is not constructed: %w", ErrPDU)
	}
	p := &PDU{Type: PDUType(tag & 0x1f)}
	r := newReader(content)
	if p.Type == PDUTrapV1 {
		if err := decodeTrapV1(&r, p); err != nil {
			return nil, err
		}
	} else {
		if err := decodeStdPDU(&r, p); err != nil {
			return nil, err
		}
	}
	if r.remaining() != 0 {
		return nil, fmt.Errorf("snmpwire: trailing PDU bytes: %w", ErrPDU)
	}
	return p, nil
}

func decodeStdPDU(r *reader, p *PDU) error {
	id, err := r.int32()
	if err != nil {
		return err
	}
	p.RequestID = id
	a, err := r.int32()
	if err != nil {
		return err
	}
	b, err := r.int32()
	if err != nil {
		return err
	}
	if p.Type == PDUGetBulk {
		p.NonRepeaters = a
		p.MaxRepetitions = b
	} else {
		p.ErrorStatus = a
		p.ErrorIndex = b
	}
	list, err := r.sequence()
	if err != nil {
		return err
	}
	p.VarBinds, err = decodeVarBinds(list)
	return err
}

func decodeTrapV1(r *reader, p *PDU) error {
	ent, err := r.oid()
	if err != nil {
		return err
	}
	p.Enterprise = ent
	addr, err := r.expect(tagIPAddress)
	if err != nil {
		return err
	}
	if len(addr) != 4 {
		return fmt.Errorf("snmpwire: Trap-v1 agent-addr must be 4 octets: %w", ErrPDU)
	}
	copy(p.AgentAddr[:], addr)
	g, err := r.int32()
	if err != nil {
		return err
	}
	p.GenericTrap = g
	s, err := r.int32()
	if err != nil {
		return err
	}
	p.SpecificTrap = s
	tsContent, err := r.expect(tagTimeTicks)
	if err != nil {
		return err
	}
	ts, err := decodeUnsigned32(tsContent)
	if err != nil {
		return err
	}
	p.Timestamp = ts
	list, err := r.sequence()
	if err != nil {
		return err
	}
	p.VarBinds, err = decodeVarBinds(list)
	return err
}

func decodeVarBinds(content []byte) ([]VarBind, error) {
	if len(content) == 0 {
		return nil, nil
	}
	r := newReader(content)
	var out []VarBind
	for r.remaining() > 0 {
		body, err := r.sequence()
		if err != nil {
			return nil, err
		}
		vr := newReader(body)
		name, err := vr.oid()
		if err != nil {
			return nil, err
		}
		tag, valContent, err := vr.tlv()
		if err != nil {
			return nil, err
		}
		val, err := decodeValue(tag, valContent)
		if err != nil {
			return nil, err
		}
		if vr.remaining() != 0 {
			return nil, fmt.Errorf("snmpwire: trailing varbind bytes: %w", ErrPDU)
		}
		out = append(out, VarBind{Name: name, Value: val})
	}
	return out, nil
}

func encodePDU(p *PDU) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("snmpwire: nil PDU: %w", ErrPDU)
	}
	if p.Type < PDUGet || p.Type > PDUReport {
		return nil, fmt.Errorf("snmpwire: unknown PDU type %d: %w", int(p.Type), ErrPDU)
	}
	var body []byte
	var err error
	if p.Type == PDUTrapV1 {
		body, err = encodeTrapV1(p)
	} else {
		body, err = encodeStdPDU(p)
	}
	if err != nil {
		return nil, err
	}
	return wrap(tagPDUBase|byte(p.Type), body), nil
}

func encodeStdPDU(p *PDU) ([]byte, error) {
	var buf []byte
	buf = append(buf, encodeInteger(int64(p.RequestID))...)
	if p.Type == PDUGetBulk {
		buf = append(buf, encodeInteger(int64(p.NonRepeaters))...)
		buf = append(buf, encodeInteger(int64(p.MaxRepetitions))...)
	} else {
		buf = append(buf, encodeInteger(int64(p.ErrorStatus))...)
		buf = append(buf, encodeInteger(int64(p.ErrorIndex))...)
	}
	list, err := encodeVarBinds(p.VarBinds)
	if err != nil {
		return nil, err
	}
	buf = append(buf, list...)
	return buf, nil
}

func encodeTrapV1(p *PDU) ([]byte, error) {
	ent, err := encodeOID(p.Enterprise)
	if err != nil {
		return nil, err
	}
	var buf []byte
	buf = append(buf, ent...)
	buf = append(buf, wrap(tagIPAddress, p.AgentAddr[:])...)
	buf = append(buf, encodeInteger(int64(p.GenericTrap))...)
	buf = append(buf, encodeInteger(int64(p.SpecificTrap))...)
	buf = append(buf, wrap(tagTimeTicks, encodeUint(uint64(p.Timestamp)))...)
	list, err := encodeVarBinds(p.VarBinds)
	if err != nil {
		return nil, err
	}
	buf = append(buf, list...)
	return buf, nil
}

func encodeVarBinds(vbs []VarBind) ([]byte, error) {
	var body []byte
	for i, vb := range vbs {
		name, err := encodeOID(vb.Name)
		if err != nil {
			return nil, fmt.Errorf("snmpwire: varbind %d name: %w", i, err)
		}
		val, err := encodeValue(vb.Value)
		if err != nil {
			return nil, fmt.Errorf("snmpwire: varbind %d value: %w", i, err)
		}
		body = append(body, encodeSequence(concat(name, val))...)
	}
	return encodeSequence(body), nil
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func cloneBytes(b []byte) []byte {
	return bytes.Clone(b)
}
