package snmpagent

import (
	"net"

	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
)

func (s *Server) handle(pkt []byte, addr net.Addr) {
	rt := s.view()
	if s == nil || rt == nil {
		return
	}
	s.syncAdmission(rt)
	pc := s.conn()
	if pc == nil {
		return
	}
	if int64(len(pkt)) > rt.MaxMessageBytes {
		s.Dropped.Add(1)
		s.observePDU("", "", "oversize")
		return
	}

	ip := peerAddr(addr)
	if !s.allowed(rt, ip) {
		s.Allowlist.Add(1)
		s.Dropped.Add(1)
		rt.record("", "", "allowlist", 0)
		s.observePDU("", "", "allowlist")
		return
	}
	if !s.global.allow("global") || !s.perIP.allow(ip.String()) {
		s.Admission.Add(1)
		s.Dropped.Add(1)
		rt.record("", "", "admission", 0)
		s.observePDU("", "", "admission")
		return
	}

	msg, err := snmpwire.DecodeMax(pkt, rt.MaxMessageBytes)
	if err != nil {
		s.Dropped.Add(1)
		s.observePDU("", "", "decode")
		return
	}
	label := versionLabel(msg.Version)
	if !rt.versionOK(label) {
		s.Dropped.Add(1)
		rt.record("", "", "version", 0)
		s.observePDU(label, pduType(msg), "version")
		return
	}

	switch msg.Version {
	case snmpwire.VersionV1, snmpwire.VersionV2c:
		s.handleCommunity(rt, pc, addr, msg)
	case snmpwire.VersionV3:
		s.handleV3(rt, pc, addr, pkt, msg)
	default:
		s.Dropped.Add(1)
		s.observePDU(label, pduType(msg), "drop")
	}
}

func (s *Server) handleCommunity(rt *Runtime, pc net.PacketConn, addr net.Addr, msg snmpwire.Message) {
	ver := versionLabel(msg.Version)
	c := rt.lookupCommunity(msg.Community)
	if c == nil {
		s.AuthFail.Add(1)
		s.Dropped.Add(1)
		rt.record(pduType(msg), "", "auth_fail", 0)
		s.observePDU(ver, pduType(msg), "auth_fail")
		return
	}
	if !c.Versions[versionLabel(msg.Version)] {
		s.Dropped.Add(1)
		rt.record(pduType(msg), c.Name, "version", 0)
		s.observePDU(ver, pduType(msg), "version")
		return
	}
	req := msg.RequestPDU()
	if req == nil || !requestPDU(req.Type) {
		s.Dropped.Add(1)
		rt.record(pduType(msg), c.Name, "drop", 0)
		s.observePDU(ver, pduType(msg), "drop")
		return
	}
	resp := rt.servePDU(msg.Version, c.Access, c.Map, *req)
	out := s.encodeCommunity(rt, msg, resp)
	if out == nil {
		s.Dropped.Add(1)
		rt.record(req.Type.String(), c.Name, "drop", resp.ErrorStatus)
		s.observePDU(ver, req.Type.String(), "drop")
		return
	}
	_, _ = pc.WriteTo(out, addr)
	s.Served.Add(1)
	rt.record(req.Type.String(), c.Name, "ok", resp.ErrorStatus)
	s.observePDU(ver, req.Type.String(), "ok")
}

func (s *Server) handleV3(rt *Runtime, pc net.PacketConn, addr net.Addr, raw []byte, msg snmpwire.Message) {
	ver := versionLabel(msg.Version)
	out := rt.Engine.Open(raw, msg)
	if len(out.Report) > 0 {
		_, _ = pc.WriteTo(out.Report, addr)
		s.Served.Add(1)
		rt.record("report", "", "ok", 0)
		s.observePDU(ver, "report", "ok")
		return
	}
	if out.Drop || out.Incoming == nil {
		s.AuthFail.Add(1)
		s.Dropped.Add(1)
		rt.record(pduType(msg), "", "auth_fail", 0)
		s.observePDU(ver, pduType(msg), "auth_fail")
		return
	}
	in := out.Incoming
	req := in.Message.RequestPDU()
	if req == nil || !requestPDU(req.Type) {
		s.Dropped.Add(1)
		rt.record(pduType(in.Message), in.User.Name, "drop", 0)
		s.observePDU(ver, pduType(in.Message), "drop")
		return
	}
	access := in.User.Access
	if access == "" {
		access = model.AccessRead
	}
	resp := rt.servePDU(snmpwire.VersionV3, access, in.User.Map, *req)
	wire, err := rt.Engine.Reply(in, resp)
	if err != nil {
		s.Dropped.Add(1)
		rt.record(req.Type.String(), in.User.Name, "drop", resp.ErrorStatus)
		s.observePDU(ver, req.Type.String(), "drop")
		return
	}
	if int64(len(wire)) > rt.MaxMessageBytes {
		resp.ErrorStatus = snmpwire.ErrorStatusTooBig
		resp.ErrorIndex = 0
		resp.VarBinds = nil
		wire, err = rt.Engine.Reply(in, resp)
		if err != nil || int64(len(wire)) > rt.MaxMessageBytes {
			s.Dropped.Add(1)
			s.observePDU(ver, req.Type.String(), "oversize")
			return
		}
	}
	_, _ = pc.WriteTo(wire, addr)
	s.Served.Add(1)
	rt.record(req.Type.String(), in.User.Name, "ok", resp.ErrorStatus)
	s.observePDU(ver, req.Type.String(), "ok")
}

func (s *Server) encodeCommunity(rt *Runtime, req snmpwire.Message, pdu snmpwire.PDU) []byte {
	msg := snmpwire.Message{
		Version:   req.Version,
		Community: append([]byte(nil), req.Community...),
		PDU:       &pdu,
	}
	b, err := snmpwire.EncodeMax(msg, rt.MaxMessageBytes)
	if err != nil {
		pdu.ErrorStatus = snmpwire.ErrorStatusTooBig
		pdu.ErrorIndex = 0
		pdu.VarBinds = nil
		msg.PDU = &pdu
		b, err = snmpwire.EncodeMax(msg, rt.MaxMessageBytes)
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

func (s *Server) observePDU(version, pdu, decision string) {
	if s == nil {
		return
	}
	dec := observability.PDUDecision(decision)
	if s.metrics != nil {
		s.metrics.Inc(observability.MetricPDUsTotal, map[string]string{
			"version":  observability.SNMPVersion(version),
			"pdu":      observability.PDUType(pdu),
			"decision": dec,
		}, 1)
		if dec == "auth_fail" {
			s.metrics.Inc(observability.MetricAuthFailTotal, map[string]string{
				"version": observability.SNMPVersion(version),
			}, 1)
		}
	}
	if s.logger == nil {
		return
	}
	s.logger.Log(observability.Record{
		Event:     observability.EventSNMPPDU,
		Component: "snmpagent",
		Result:    dec,
	})
	if dec == "auth_fail" {
		s.logger.Log(observability.Record{
			Event:     observability.EventAuthFailure,
			Component: "snmpagent",
			Level:     observability.LevelWarn,
			Result:    dec,
		})
	}
}
