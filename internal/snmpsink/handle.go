package snmpsink

import (
	"bytes"
	"net"

	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
	"github.com/hilather/go-lab-snmp/internal/store"
	"github.com/hilather/go-lab-snmp/internal/usm"
)

func (s *Server) handle(pkt []byte, addr net.Addr) {
	if s == nil || s.cfg.Store == nil {
		return
	}
	pc := s.conn()
	if pc == nil {
		return
	}
	if int64(len(pkt)) > s.cfg.MaxMessageBytes {
		s.Dropped.Add(1)
		return
	}

	ip := peerAddr(addr)
	if !s.allowed(ip) {
		s.Allowlist.Add(1)
		s.Dropped.Add(1)
		return
	}
	if !s.global.allow("global") || !s.perIP.allow(ip.String()) {
		s.Admission.Add(1)
		s.Dropped.Add(1)
		return
	}

	msg, err := snmpwire.DecodeMax(pkt, s.cfg.MaxMessageBytes)
	if err != nil {
		if s.cfg.AcceptUnauthenticated {
			s.storeBestEffort(pkt, addr, "decode: "+err.Error())
			return
		}
		s.Dropped.Add(1)
		return
	}

	switch msg.Version {
	case snmpwire.VersionV1, snmpwire.VersionV2c:
		s.handleCommunity(pc, addr, pkt, msg)
	case snmpwire.VersionV3:
		s.handleV3(pc, addr, pkt, msg)
	default:
		s.Dropped.Add(1)
	}
}

func (s *Server) handleCommunity(pc net.PacketConn, addr net.Addr, raw []byte, msg snmpwire.Message) {
	c := s.lookupCommunity(msg.Community)
	if c == nil {
		s.AuthFail.Add(1)
		if !s.cfg.AcceptUnauthenticated {
			s.Dropped.Add(1)
			return
		}
		s.storePDU(raw, addr, msg, "", "", "unauthenticated")
		return
	}
	req := msg.RequestPDU()
	if req == nil || !trapPDU(req.Type) {
		s.Dropped.Add(1)
		return
	}
	s.storeAndAck(pc, addr, raw, msg, c.Name, "", "")
}

func (s *Server) handleV3(pc net.PacketConn, addr net.Addr, raw []byte, msg snmpwire.Message) {
	if s.cfg.Engine == nil {
		s.authFail(raw, addr, msg)
		return
	}
	in, report := s.openV3(raw, msg)
	if len(report) > 0 {
		ack(pc, addr, report)
		return
	}
	if in == nil {
		s.authFail(raw, addr, msg)
		return
	}
	req := in.Message.RequestPDU()
	if req == nil || !trapPDU(req.Type) {
		s.Dropped.Add(1)
		return
	}
	s.storeAndAck(pc, addr, raw, in.Message, "", in.User.Name, "")
}

func (s *Server) openV3(raw []byte, msg snmpwire.Message) (*usm.Incoming, []byte) {
	eng := s.cfg.Engine
	if bytes.Equal(msg.USM.EngineID, eng.ID()) || len(msg.USM.EngineID) == 0 {
		out := eng.Open(raw, msg)
		if len(out.Report) > 0 {
			return nil, out.Report
		}
		if out.Incoming != nil {
			return out.Incoming, nil
		}
		return nil, nil
	}
	out := eng.OpenNotification(raw, msg)
	if out.Incoming != nil {
		return out.Incoming, nil
	}
	return nil, nil
}

func (s *Server) authFail(raw []byte, addr net.Addr, msg snmpwire.Message) {
	s.AuthFail.Add(1)
	if !s.cfg.AcceptUnauthenticated {
		s.Dropped.Add(1)
		return
	}
	user := string(msg.USM.UserName)
	s.storePDU(raw, addr, msg, "", user, "unauthenticated")
}

func (s *Server) storeAndAck(pc net.PacketConn, addr net.Addr, raw []byte, msg snmpwire.Message, community, user, warning string) {
	if !s.storePDU(raw, addr, msg, community, user, warning) {
		return
	}
	req := msg.RequestPDU()
	if req == nil || req.Type != snmpwire.PDUInform {
		return
	}
	s.ackInform(pc, addr, msg, *req)
}

func (s *Server) storePDU(raw []byte, addr net.Addr, msg snmpwire.Message, community, user, warning string) bool {
	rec := recordFrom(msg, community, user, addrString(addr), warning, s.cfg.Clock.Now())
	if s.cfg.RawRetain {
		rec.Raw = append([]byte(nil), raw...)
	}
	rec.Size = int64(len(raw))
	if _, err := s.cfg.Store.Insert(rec); err != nil {
		s.Dropped.Add(1)
		return false
	}
	s.Stored.Add(1)
	return true
}

func (s *Server) storeBestEffort(raw []byte, addr net.Addr, warning string) {
	rec := store.TrapRecord{
		ReceivedAt:   s.cfg.Clock.Now(),
		RemoteAddr:   addrString(addr),
		ParseWarning: warning,
	}
	if s.cfg.RawRetain {
		rec.Raw = append([]byte(nil), raw...)
	}
	rec.Size = int64(len(raw))
	if _, err := s.cfg.Store.Insert(rec); err != nil {
		s.Dropped.Add(1)
		return
	}
	s.Stored.Add(1)
}

func (s *Server) ackInform(pc net.PacketConn, addr net.Addr, msg snmpwire.Message, req snmpwire.PDU) {
	resp := snmpwire.PDU{
		Type:      snmpwire.PDUResponse,
		RequestID: req.RequestID,
		VarBinds:  req.VarBinds,
	}
	var out []byte
	var err error
	if msg.Version == snmpwire.VersionV3 {
		if s.cfg.Engine == nil {
			return
		}
		in := &usm.Incoming{User: s.cfg.Engine.User(string(msg.USM.UserName)), Message: msg}
		if msg.ScopedPDU != nil {
			in.ScopedPDU = *msg.ScopedPDU
		}
		if in.User == nil {
			return
		}
		out, err = s.cfg.Engine.Reply(in, resp)
	} else {
		out, err = snmpwire.EncodeMax(snmpwire.Message{
			Version:   msg.Version,
			Community: append([]byte(nil), msg.Community...),
			PDU:       &resp,
		}, s.cfg.MaxMessageBytes)
	}
	if err != nil || len(out) == 0 {
		return
	}
	ack(pc, addr, out)
	s.InformAck.Add(1)
}

// ack is the INFORM (and v3 Report) reply path. WriteTo on the trap
// socket; never Dial.
func ack(pc net.PacketConn, addr net.Addr, payload []byte) {
	if pc == nil || addr == nil || len(payload) == 0 {
		return
	}
	_, _ = pc.WriteTo(payload, addr)
}

func (s *Server) lookupCommunity(wire []byte) *Community {
	if s == nil || len(s.cfg.Communities) == 0 {
		return nil
	}
	return s.cfg.Communities[string(wire)]
}

func trapPDU(t snmpwire.PDUType) bool {
	switch t {
	case snmpwire.PDUTrapV1, snmpwire.PDUTrapV2, snmpwire.PDUInform:
		return true
	default:
		return false
	}
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func versionLabel(v snmpwire.Version) string {
	switch v {
	case snmpwire.VersionV1:
		return model.VersionV1
	case snmpwire.VersionV2c:
		return model.VersionV2c
	case snmpwire.VersionV3:
		return model.VersionV3
	default:
		return v.String()
	}
}
