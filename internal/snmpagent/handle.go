package snmpagent

import (
	"net"

	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
)

func (s *Server) handle(pkt []byte, addr net.Addr) {
	if s == nil || s.rt == nil {
		return
	}
	pc := s.conn()
	if pc == nil {
		return
	}
	if int64(len(pkt)) > s.rt.MaxMessageBytes {
		s.Dropped.Add(1)
		return
	}

	ip := peerAddr(addr)
	if !s.allowed(ip) {
		s.Allowlist.Add(1)
		s.Dropped.Add(1)
		s.rt.record("", "", "allowlist", 0)
		return
	}
	if !s.global.allow("global") || !s.perIP.allow(ip.String()) {
		s.Admission.Add(1)
		s.Dropped.Add(1)
		s.rt.record("", "", "admission", 0)
		return
	}

	msg, err := snmpwire.DecodeMax(pkt, s.rt.MaxMessageBytes)
	if err != nil {
		s.Dropped.Add(1)
		return
	}
	label := versionLabel(msg.Version)
	if !s.rt.versionOK(label) {
		s.Dropped.Add(1)
		s.rt.record("", "", "version", 0)
		return
	}

	switch msg.Version {
	case snmpwire.VersionV1, snmpwire.VersionV2c:
		s.handleCommunity(pc, addr, msg)
	case snmpwire.VersionV3:
		s.handleV3(pc, addr, pkt, msg)
	default:
		s.Dropped.Add(1)
	}
}

func (s *Server) handleCommunity(pc net.PacketConn, addr net.Addr, msg snmpwire.Message) {
	c := s.rt.lookupCommunity(msg.Community)
	if c == nil {
		s.AuthFail.Add(1)
		s.Dropped.Add(1)
		s.rt.record(pduType(msg), "", "auth_fail", 0)
		return
	}
	if !c.Versions[versionLabel(msg.Version)] {
		s.Dropped.Add(1)
		s.rt.record(pduType(msg), c.Name, "version", 0)
		return
	}
	req := msg.RequestPDU()
	if req == nil || !requestPDU(req.Type) {
		s.Dropped.Add(1)
		s.rt.record(pduType(msg), c.Name, "drop", 0)
		return
	}
	resp := s.rt.servePDU(msg.Version, c.Access, c.Map, *req)
	out := s.encodeCommunity(msg, resp)
	if out == nil {
		s.Dropped.Add(1)
		s.rt.record(req.Type.String(), c.Name, "drop", resp.ErrorStatus)
		return
	}
	_, _ = pc.WriteTo(out, addr)
	s.Served.Add(1)
	s.rt.record(req.Type.String(), c.Name, "ok", resp.ErrorStatus)
}

func (s *Server) handleV3(pc net.PacketConn, addr net.Addr, raw []byte, msg snmpwire.Message) {
	out := s.rt.Engine.Open(raw, msg)
	if len(out.Report) > 0 {
		_, _ = pc.WriteTo(out.Report, addr)
		s.Served.Add(1)
		s.rt.record("report", "", "ok", 0)
		return
	}
	if out.Drop || out.Incoming == nil {
		s.AuthFail.Add(1)
		s.Dropped.Add(1)
		s.rt.record(pduType(msg), "", "auth_fail", 0)
		return
	}
	in := out.Incoming
	req := in.Message.RequestPDU()
	if req == nil || !requestPDU(req.Type) {
		s.Dropped.Add(1)
		s.rt.record(pduType(in.Message), in.User.Name, "drop", 0)
		return
	}
	access := in.User.Access
	if access == "" {
		access = model.AccessRead
	}
	resp := s.rt.servePDU(snmpwire.VersionV3, access, in.User.Map, *req)
	wire, err := s.rt.Engine.Reply(in, resp)
	if err != nil {
		s.Dropped.Add(1)
		s.rt.record(req.Type.String(), in.User.Name, "drop", resp.ErrorStatus)
		return
	}
	if int64(len(wire)) > s.rt.MaxMessageBytes {
		resp.ErrorStatus = snmpwire.ErrorStatusTooBig
		resp.ErrorIndex = 0
		resp.VarBinds = nil
		wire, err = s.rt.Engine.Reply(in, resp)
		if err != nil || int64(len(wire)) > s.rt.MaxMessageBytes {
			s.Dropped.Add(1)
			return
		}
	}
	_, _ = pc.WriteTo(wire, addr)
	s.Served.Add(1)
	s.rt.record(req.Type.String(), in.User.Name, "ok", resp.ErrorStatus)
}

func (s *Server) encodeCommunity(req snmpwire.Message, pdu snmpwire.PDU) []byte {
	msg := snmpwire.Message{
		Version:   req.Version,
		Community: append([]byte(nil), req.Community...),
		PDU:       &pdu,
	}
	b, err := snmpwire.EncodeMax(msg, s.rt.MaxMessageBytes)
	if err != nil {
		pdu.ErrorStatus = snmpwire.ErrorStatusTooBig
		pdu.ErrorIndex = 0
		pdu.VarBinds = nil
		msg.PDU = &pdu
		b, err = snmpwire.EncodeMax(msg, s.rt.MaxMessageBytes)
		if err != nil {
			return nil
		}
	}
	return b
}

func requestPDU(t snmpwire.PDUType) bool {
	switch t {
	case snmpwire.PDUGet, snmpwire.PDUGetNext, snmpwire.PDUGetBulk, snmpwire.PDUSet:
		return true
	default:
		return false
	}
}

func pduType(msg snmpwire.Message) string {
	p := msg.RequestPDU()
	if p == nil {
		return ""
	}
	return p.Type.String()
}
