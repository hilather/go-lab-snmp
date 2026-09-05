package snmpsink

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snmptest"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
	"github.com/hilather/go-lab-snmp/internal/usm"
)

func TestTrapV2Stored(t *testing.T) {
	s := startSink(t, Config{})
	req := snmptest.MustEncodeTrapV2(t, "public", 14, coldStart())
	snmptest.MustSend(t, dst(s), req)
	rec := waitOne(t, s)
	if rec.PDUType != "trapv2" || rec.Community != "public" || rec.NotificationOID != coldStart().String() {
		t.Fatalf("%+v", rec)
	}
	if rec.Version != model.VersionV2c || rec.User != "" {
		t.Fatalf("%+v", rec)
	}
	if len(rec.Raw) == 0 || rec.ID == "" || rec.RemoteAddr == "" {
		t.Fatalf("id/raw/remote %+v", rec)
	}
}

func TestTrapV1Stored(t *testing.T) {
	s := startSink(t, Config{})
	b, err := snmptest.EncodeTrapV1("public", snmpwire.PDU{
		Enterprise:  snmpwire.OID{1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1},
		AgentAddr:   [4]byte{127, 0, 0, 1},
		GenericTrap: snmpwire.TrapColdStart,
		Timestamp:   100,
	})
	if err != nil {
		t.Fatal(err)
	}
	snmptest.MustSend(t, dst(s), b)
	rec := waitOne(t, s)
	if rec.PDUType != "trapv1" || rec.NotificationOID != "1.3.6.1.6.3.1.1.5.1" {
		t.Fatalf("%+v", rec)
	}
}

func TestInformWriteToSource(t *testing.T) {
	s := startSink(t, Config{})
	req := snmptest.MustEncodeInform(t, "public", 15, coldStart())
	m := snmptest.MustExchange(t, dst(s), req, 2*time.Second)
	p := m.RequestPDU()
	if p == nil || p.Type != snmpwire.PDUResponse || p.RequestID != 15 {
		t.Fatalf("INFORM ack %+v", p)
	}
	if s.InformAck.Load() < 1 {
		t.Fatal("InformAck")
	}
	rec := waitOne(t, s)
	if rec.PDUType != "inform" || rec.Community != "public" {
		t.Fatalf("%+v", rec)
	}
}

func TestInformAckCountedBeforeWriteTo(t *testing.T) {
	s := startSink(t, Config{})
	wrapPacketConn(t, s, func(pc net.PacketConn) net.PacketConn {
		return &orderPC{PacketConn: pc, acks: &s.InformAck, t: t}
	})
	req := snmptest.MustEncodeInform(t, "public", 16, coldStart())
	m := snmptest.MustExchange(t, dst(s), req, 2*time.Second)
	p := m.RequestPDU()
	if p == nil || p.Type != snmpwire.PDUResponse || p.RequestID != 16 {
		t.Fatalf("INFORM ack %+v", p)
	}
	if s.InformAck.Load() < 1 {
		t.Fatal("InformAck")
	}
}

type orderPC struct {
	net.PacketConn
	acks *atomic.Int64
	t    *testing.T
}

func (o *orderPC) WriteTo(p []byte, addr net.Addr) (int, error) {
	if o.acks.Load() < 1 {
		o.t.Error("InformAck must increment before WriteTo")
	}
	return o.PacketConn.WriteTo(p, addr)
}

func TestInformWriteToListenPacket(t *testing.T) {
	s := startSink(t, Config{})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	req := snmptest.MustEncodeInform(t, "public", 99, coldStart())
	sinkAddr, err := net.ResolveUDPAddr("udp", dst(s))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.WriteTo(req, sinkAddr); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64<<10)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("INFORM must WriteTo source: %v", err)
	}
	if from.String() != dst(s) {
		t.Fatalf("ack from %s want %s", from, dst(s))
	}
	got, err := snmpwire.Decode(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	p := got.RequestPDU()
	if p == nil || p.Type != snmpwire.PDUResponse || p.RequestID != 99 {
		t.Fatalf("%+v", p)
	}
}

func TestUnauthDrop(t *testing.T) {
	s := startSink(t, Config{})
	req := snmptest.MustEncodeTrapV2(t, "nope", 1, coldStart())
	snmptest.MustSend(t, dst(s), req)
	time.Sleep(50 * time.Millisecond)
	if s.AuthFail.Load() < 1 {
		t.Fatal("AuthFail")
	}
	if s.Store().Stats().Messages != 0 {
		t.Fatalf("unauth trap stored: %+v", s.Store().Stats())
	}
}

func TestAcceptUnauthenticatedStores(t *testing.T) {
	s := startSink(t, Config{AcceptUnauthenticated: true})
	req := snmptest.MustEncodeTrapV2(t, "nope", 1, coldStart())
	snmptest.MustSend(t, dst(s), req)
	rec := waitOne(t, s)
	if rec.Community != "" || rec.User != "" {
		t.Fatalf("must not store wire identity: %+v", rec)
	}
	if rec.ParseWarning == "" {
		t.Fatal("parseWarning")
	}
}

func TestAcceptUnauthenticatedDoesNotStoreGet(t *testing.T) {
	s := startSink(t, Config{AcceptUnauthenticated: true})
	req := snmptest.MustEncodeGet(t, snmpwire.VersionV2c, "nope", 1, snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0})
	snmptest.MustSend(t, dst(s), req)
	time.Sleep(50 * time.Millisecond)
	if s.AuthFail.Load() < 1 {
		t.Fatal("AuthFail")
	}
	if s.Store().Stats().Messages != 0 {
		t.Fatal("GET must not enter the trap inbox")
	}
}

func TestV3TrapRemoteEngine(t *testing.T) {
	eng := aliceEngine(t)
	s := startSink(t, Config{Engine: eng})
	sender := remoteEngine(t)
	pdu := snmptest.TrapV2PDU(7, coldStart())
	wire := wrapTrap(t, sender, pdu, false)
	snmptest.MustSend(t, dst(s), wire)
	rec := waitOne(t, s)
	if rec.Version != model.VersionV3 || rec.User != "alice" || rec.PDUType != "trapv2" {
		t.Fatalf("%+v", rec)
	}
	if rec.Community != "" {
		t.Fatalf("user trap leaked community %+v", rec)
	}
}

func TestV3InformWriteToAuthenticatedResponse(t *testing.T) {
	eng := aliceEngine(t)
	s := startSink(t, Config{Engine: eng})
	pdu := snmptest.TrapV2PDU(8, coldStart())
	pdu.Type = snmpwire.PDUInform
	wire := wrapTrap(t, eng, pdu, true)
	raw, err := snmptest.Exchange(dst(s), wire, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	m := snmptest.MustDecode(t, raw)
	if !m.Auth() || !m.Priv() {
		t.Fatalf("INFORM Response must be authenticated flags=%02x", m.MsgFlags)
	}
	out := eng.Open(raw, m)
	if out.Incoming == nil {
		t.Fatalf("response not openable report=%v drop=%v", out.Report != nil, out.Drop)
	}
	p := out.Incoming.ScopedPDU.PDU
	if p.Type != snmpwire.PDUResponse || p.RequestID != 8 {
		t.Fatalf("%+v", p)
	}
	rec := waitOne(t, s)
	if rec.PDUType != "inform" || rec.User != "alice" {
		t.Fatalf("%+v", rec)
	}
}

func TestV3UnknownUserDrop(t *testing.T) {
	eng := aliceEngine(t)
	s := startSink(t, Config{Engine: eng})
	other, err := usm.New(usm.Config{EngineID: eng.ID(), EngineBoots: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.AddUser(usm.UserConfig{Name: "bob", Level: model.LevelNoAuthNoPriv}); err != nil {
		t.Fatal(err)
	}
	msg := snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            3,
		MsgMaxSize:       65507,
		MsgFlags:         usm.Flags(model.LevelNoAuthNoPriv, false),
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		ScopedPDU:        &snmpwire.ScopedPDU{PDU: snmptest.TrapV2PDU(3, coldStart())},
	}
	wire, err := other.Wrap(other.User("bob"), msg)
	if err != nil {
		t.Fatal(err)
	}
	snmptest.MustSend(t, dst(s), wire)
	time.Sleep(50 * time.Millisecond)
	if s.AuthFail.Load() < 1 {
		t.Fatal("AuthFail")
	}
	if s.Store().Stats().Messages != 0 {
		t.Fatal("unknown user stored")
	}
}

func TestV3InformUnknownUserReportAuthFail(t *testing.T) {
	eng := aliceEngine(t)
	s := startSink(t, Config{Engine: eng})
	other, err := usm.New(usm.Config{EngineID: eng.ID(), EngineBoots: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.AddUser(usm.UserConfig{Name: "bob", Level: model.LevelNoAuthNoPriv}); err != nil {
		t.Fatal(err)
	}
	pdu := snmptest.TrapV2PDU(4, coldStart())
	pdu.Type = snmpwire.PDUInform
	msg := snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            4,
		MsgMaxSize:       65507,
		MsgFlags:         usm.Flags(model.LevelNoAuthNoPriv, true),
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		ScopedPDU:        &snmpwire.ScopedPDU{PDU: pdu},
	}
	wire, err := other.Wrap(other.User("bob"), msg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := snmptest.Exchange(dst(s), wire, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got := snmptest.MustDecode(t, raw)
	p := got.RequestPDU()
	if p == nil || p.Type != snmpwire.PDUReport {
		t.Fatalf("want Report got %+v", p)
	}
	if s.AuthFail.Load() < 1 {
		t.Fatal("AuthFail")
	}
	if s.Store().Stats().Messages != 0 {
		t.Fatal("unknown user INFORM must not store by default")
	}
}

func TestV3InformUnknownUserAcceptStores(t *testing.T) {
	eng := aliceEngine(t)
	s := startSink(t, Config{Engine: eng, AcceptUnauthenticated: true})
	other, err := usm.New(usm.Config{EngineID: eng.ID(), EngineBoots: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := other.AddUser(usm.UserConfig{Name: "bob", Level: model.LevelNoAuthNoPriv}); err != nil {
		t.Fatal(err)
	}
	pdu := snmptest.TrapV2PDU(5, coldStart())
	pdu.Type = snmpwire.PDUInform
	msg := snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            5,
		MsgMaxSize:       65507,
		MsgFlags:         usm.Flags(model.LevelNoAuthNoPriv, true),
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		ScopedPDU:        &snmpwire.ScopedPDU{PDU: pdu},
	}
	wire, err := other.Wrap(other.User("bob"), msg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := snmptest.Exchange(dst(s), wire, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got := snmptest.MustDecode(t, raw)
	if p := got.RequestPDU(); p == nil || p.Type != snmpwire.PDUReport {
		t.Fatalf("want Report got %+v", got.RequestPDU())
	}
	rec := waitOne(t, s)
	if rec.User != "" {
		t.Fatalf("must not store wire userName: %+v", rec)
	}
	if rec.PDUType != "inform" || rec.ParseWarning == "" {
		t.Fatalf("%+v", rec)
	}
}

func TestCommunityVersionDrop(t *testing.T) {
	s := startSink(t, Config{
		Communities: map[string]*Community{
			"public": {
				Name:     "public",
				Wire:     []byte("public"),
				Versions: map[string]bool{model.VersionV1: true},
			},
		},
	})
	req := snmptest.MustEncodeTrapV2(t, "public", 1, coldStart())
	snmptest.MustSend(t, dst(s), req)
	time.Sleep(50 * time.Millisecond)
	if s.Store().Stats().Messages != 0 {
		t.Fatal("v2c trap on v1-only community must drop")
	}
	if s.AuthFail.Load() != 0 {
		t.Fatal("version mismatch is not auth_fail")
	}
}

func TestAgentVersionsDropV3(t *testing.T) {
	eng := aliceEngine(t)
	s := startSink(t, Config{
		Engine:   eng,
		Versions: map[string]bool{model.VersionV1: true, model.VersionV2c: true},
	})
	sender := remoteEngine(t)
	wire := wrapTrap(t, sender, snmptest.TrapV2PDU(9, coldStart()), false)
	snmptest.MustSend(t, dst(s), wire)
	time.Sleep(50 * time.Millisecond)
	if s.Store().Stats().Messages != 0 {
		t.Fatal("v3 trap must drop when agent versions omit v3")
	}
	if s.AuthFail.Load() != 0 {
		t.Fatal("disabled version is not auth_fail")
	}
}

func TestGetOnTrapPortDropped(t *testing.T) {
	s := startSink(t, Config{})
	req := snmptest.MustEncodeGet(t, snmpwire.VersionV2c, "public", 1, snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0})
	snmptest.MustSend(t, dst(s), req)
	time.Sleep(50 * time.Millisecond)
	if s.Store().Stats().Messages != 0 {
		t.Fatal("GET must not enter the trap inbox")
	}
}

func TestStoreWaitExistingInsertedTimeoutWipe(t *testing.T) {
	// Locked wait matrix lives in internal/store; this guards the sink wiring.
	s := startSink(t, Config{})
	req := snmptest.MustEncodeTrapV2(t, "public", 1, coldStart())
	snmptest.MustSend(t, dst(s), req)
	rec := waitOne(t, s)
	if rec.PDUType != "trapv2" {
		t.Fatalf("%+v", rec)
	}
	s.Store().Wipe()
	if s.Store().Stats().Messages != 0 {
		t.Fatal("wipe")
	}
}

func TestListenPacketUDP(t *testing.T) {
	s := startSink(t, Config{Addr: "127.0.0.1:0"})
	if s.Addr() == nil {
		t.Fatal("bound addr")
	}
}

func TestRebindMovesPacketConn(t *testing.T) {
	s := startSink(t, Config{})
	old := s.Addr().String()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	next := pc.LocalAddr().String()
	_ = pc.Close()
	if err := s.Rebind(next); err != nil {
		t.Fatal(err)
	}
	if got := s.Addr().String(); got != next {
		t.Fatalf("addr %s want %s", got, next)
	}
	req := snmptest.MustEncodeInform(t, "public", 21, coldStart())
	m := snmptest.MustExchange(t, next, req, 2*time.Second)
	p := m.RequestPDU()
	if p == nil || p.Type != snmpwire.PDUResponse {
		t.Fatalf("INFORM after rebind %+v", p)
	}
	hold, err := net.ListenPacket("udp", old)
	if err != nil {
		t.Fatalf("old PacketConn must be closed: %v", err)
	}
	_ = hold.Close()
}

func TestRebindEmptyUnbinds(t *testing.T) {
	s := startSink(t, Config{})
	old := s.Addr().String()
	if err := s.Rebind(""); err != nil {
		t.Fatal(err)
	}
	if s.Bound() {
		t.Fatal("empty addr must unbind")
	}
	hold, err := net.ListenPacket("udp", old)
	if err != nil {
		t.Fatalf("unbound address must be free: %v", err)
	}
	_ = hold.Close()
}
