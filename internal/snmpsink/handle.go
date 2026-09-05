package snmpsink

import (
	"bytes"
	"net"

	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
	"github.com/hilather/go-lab-snmp/internal/store"
	"github.com/hilather/go-lab-snmp/internal/usm"
)

// replySink is one notification's write path (UDP WriteTo, TCP WriteTCP, DTLS Write).
type replySink interface {
	Write(p []byte) error
	RemoteAddr() net.Addr
}

type udpReply struct {
	pc   net.PacketConn
	addr net.Addr
}

func (u udpReply) Write(p []byte) error {
	_, err := u.pc.WriteTo(p, u.addr)
	return err
}

func (u udpReply) RemoteAddr() net.Addr { return u.addr }

type streamReply struct {
	conn net.Conn
	tcp  bool
}

func (r streamReply) Write(p []byte) error {
	if r.conn == nil {
		return net.ErrClosed
	}
	if r.tcp {
		return snmpwire.WriteTCP(r.conn, p)
	}
	_, err := r.conn.Write(p)
	return err
}

func (r streamReply) RemoteAddr() net.Addr {
	if r.conn == nil {
		return nil
	}
	return r.conn.RemoteAddr()
}

func (s *Server) handle(sink replySink, pkt []byte) {
	if s == nil || s.cfg.Store == nil || sink == nil {
		return
	}
	s.syncAdmission()
	if int64(len(pkt)) > s.maxMessageBytes() {
		s.Dropped.Add(1)
		s.observeTrap("", "oversize")
		return
	}

	addr := sink.RemoteAddr()
	ip := peerAddr(addr)
	if !s.allowed(ip) {
		s.Allowlist.Add(1)
		s.Dropped.Add(1)
		s.observeTrap("", "allowlist")
		return
	}
	if !s.global.allow("global") || !s.perIP.allow(ip.String()) {
		s.Admission.Add(1)
		s.Dropped.Add(1)
		s.observeTrap("", "admission")
		return
	}

	msg, err := snmpwire.DecodeMax(pkt, s.maxMessageBytes())
	if err != nil {
		if s.acceptUnauth() {
			s.storeBestEffort(pkt, addr, "decode: "+err.Error())
			return
		}
		s.Dropped.Add(1)
		s.observeTrap("", "decode")
		return
	}
	ver := versionLabel(msg.Version)
	if !s.versionOK(ver) {
		s.Dropped.Add(1)
		s.observeTrap(ver, "version")
		return
	}

	switch msg.Version {
	case snmpwire.VersionV1, snmpwire.VersionV2c:
		s.handleCommunity(sink, pkt, msg)
	case snmpwire.VersionV3:
		s.handleV3(sink, pkt, msg)
	default:
		s.Dropped.Add(1)
		s.observeTrap(ver, "drop")
	}
}

func (s *Server) handleCommunity(sink replySink, raw []byte, msg snmpwire.Message) {
	ver := versionLabel(msg.Version)
	c := s.lookupCommunity(msg.Community)
	if c == nil {
		s.authFail(raw, sink.RemoteAddr(), msg)
		return
	}
	if !communityVersionOK(c, versionLabel(msg.Version)) {
		s.Dropped.Add(1)
		s.observeTrap(ver, "version")
		return
	}
	req := msg.RequestPDU()
	if req == nil || !trapPDU(req.Type) {
		s.Dropped.Add(1)
		s.observeTrap(ver, "drop")
		return
	}
	s.storeAndAck(sink, raw, msg, c.Name, "", "")
}

func (s *Server) handleV3(sink replySink, raw []byte, msg snmpwire.Message) {
	if s.engine() == nil {
		s.authFail(raw, sink.RemoteAddr(), msg)
		return
	}
	in, report, discovery := s.openV3(raw, msg)
	if len(report) > 0 {
		if !discovery {
			s.authFail(raw, sink.RemoteAddr(), msg)
		}
		ack(sink, report)
		return
	}
	if in == nil {
		s.authFail(raw, sink.RemoteAddr(), msg)
		return
	}
	req := in.Message.RequestPDU()
	if req == nil || !trapPDU(req.Type) {
		s.Dropped.Add(1)
		return
	}
	s.storeAndAck(sink, raw, in.Message, "", in.User.Name, "")
}

func (s *Server) openV3(raw []byte, msg snmpwire.Message) (in *usm.Incoming, report []byte, discovery bool) {
	eng := s.engine()
	if len(msg.USM.EngineID) == 0 || bytes.Equal(msg.USM.EngineID, eng.ID()) {
		out := eng.Open(raw, msg)
		if len(out.Report) > 0 {
			return nil, out.Report, len(msg.USM.EngineID) == 0
		}
		if out.Incoming != nil {
			return out.Incoming, nil, false
		}
		return nil, nil, false
	}
	out := eng.OpenNotification(raw, msg)
	if out.Incoming != nil {
		return out.Incoming, nil, false
	}
	return nil, nil, false
}

func (s *Server) authFail(raw []byte, addr net.Addr, msg snmpwire.Message) {
	s.AuthFail.Add(1)
	if !s.acceptUnauth() {
		s.Dropped.Add(1)
		s.observeTrap(versionLabel(msg.Version), "auth_fail")
		return
	}
	s.storeUnauthTrap(raw, addr, msg, unauthWarning(msg))
}

func (s *Server) storeAndAck(sink replySink, raw []byte, msg snmpwire.Message, community, user, warning string) {
	if !s.storePDU(raw, sink.RemoteAddr(), msg, community, user, warning) {
		return
	}
	req := msg.RequestPDU()
	if req == nil || req.Type != snmpwire.PDUInform {
		return
	}
	s.ackInform(sink, msg, *req)
}

func (s *Server) storeUnauthTrap(raw []byte, addr net.Addr, msg snmpwire.Message, warning string) {
	req := msg.RequestPDU()
	if req == nil || !trapPDU(req.Type) {
		s.Dropped.Add(1)
		return
	}
	s.storePDU(raw, addr, msg, "", "", warning)
}

func unauthWarning(msg snmpwire.Message) string {
	if msg.Version == snmpwire.VersionV3 {
		if n := string(msg.USM.UserName); n != "" {
			return "unauthenticated user " + n
		}
	}
	return "unauthenticated"
}

func (s *Server) storePDU(raw []byte, addr net.Addr, msg snmpwire.Message, community, user, warning string) bool {
	rec := recordFrom(msg, community, user, addrString(addr), warning, s.cfg.Clock.Now())
	if s.rawRetain() {
		rec.Raw = append([]byte(nil), raw...)
	}
	rec.Size = int64(len(raw))
	if _, err := s.cfg.Store.Insert(rec); err != nil {
		s.Dropped.Add(1)
		s.observeTrap(rec.Version, "drop")
		return false
	}
	s.Stored.Add(1)
	s.observeTrap(rec.Version, "ok")
	return true
}

func (s *Server) storeBestEffort(raw []byte, addr net.Addr, warning string) {
	rec := store.TrapRecord{
		ReceivedAt:   s.cfg.Clock.Now(),
		RemoteAddr:   addrString(addr),
		ParseWarning: warning,
	}
	if s.rawRetain() {
		rec.Raw = append([]byte(nil), raw...)
	}
	rec.Size = int64(len(raw))
	if _, err := s.cfg.Store.Insert(rec); err != nil {
		s.Dropped.Add(1)
		s.observeTrap(rec.Version, "drop")
		return
	}
	s.Stored.Add(1)
	s.observeTrap(rec.Version, "ok")
}

func (s *Server) ackInform(sink replySink, msg snmpwire.Message, req snmpwire.PDU) {
	resp := snmpwire.PDU{
		Type:      snmpwire.PDUResponse,
		RequestID: req.RequestID,
		VarBinds:  req.VarBinds,
	}
	var out []byte
	var err error
	if msg.Version == snmpwire.VersionV3 {
		eng := s.engine()
		if eng == nil {
			return
		}
		in := &usm.Incoming{User: eng.User(string(msg.USM.UserName)), Message: msg}
		if msg.ScopedPDU != nil {
			in.ScopedPDU = *msg.ScopedPDU
		}
		if in.User == nil {
			return
		}
		out, err = eng.Reply(in, resp)
	} else {
		out, err = snmpwire.EncodeMax(snmpwire.Message{
			Version:   msg.Version,
			Community: append([]byte(nil), msg.Community...),
			PDU:       &resp,
		}, s.maxMessageBytes())
	}
	if err != nil || len(out) == 0 {
		return
	}
	s.InformAck.Add(1)
	ack(sink, out)
}

// ack is the INFORM and v3 Report reply path. UDP WriteTo, TCP WriteTCP,
// DTLS Write on the accepted connection; never Dial.
func ack(sink replySink, payload []byte) {
	if sink == nil || len(payload) == 0 {
		return
	}
	_ = sink.Write(payload)
}

func (s *Server) lookupCommunity(wire []byte) *Community {
	if s == nil {
		return nil
	}
	if snap := s.snap(); snap != nil {
		c := snap.LookupCommunity(wire)
		if c == nil {
			return nil
		}
		return &Community{Name: c.Name, Wire: c.Wire, Versions: c.Versions}
	}
	if len(s.cfg.Communities) == 0 {
		return nil
	}
	return s.cfg.Communities[string(wire)]
}

func (s *Server) versionOK(label string) bool {
	if s == nil {
		return true
	}
	if snap := s.snap(); snap != nil {
		return snap.VersionOK(label)
	}
	if len(s.cfg.Versions) == 0 {
		return true
	}
	return s.cfg.Versions[label]
}

func communityVersionOK(c *Community, label string) bool {
	if c == nil || len(c.Versions) == 0 {
		return true
	}
	return c.Versions[label]
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

func (s *Server) observeTrap(version, decision string) {
	if s == nil {
		return
	}
	dec := observability.TrapDecision(decision)
	if s.cfg.Metrics != nil {
		s.cfg.Metrics.Inc(observability.MetricTrapsTotal, map[string]string{
			"version":  observability.SNMPVersion(version),
			"decision": dec,
		}, 1)
		if dec == "auth_fail" {
			s.cfg.Metrics.Inc(observability.MetricAuthFailTotal, map[string]string{
				"version": observability.SNMPVersion(version),
			}, 1)
		}
	}
	if s.cfg.Logger == nil {
		return
	}
	s.cfg.Logger.Log(observability.Record{
		Event:     observability.EventSNMPTrap,
		Component: "snmpsink",
		Result:    dec,
	})
	if dec == "auth_fail" {
		s.cfg.Logger.Log(observability.Record{
			Event:     observability.EventAuthFailure,
			Component: "snmpsink",
			Level:     observability.LevelWarn,
			Result:    dec,
		})
	}
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
