package snmpagent

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
	"github.com/hilather/go-lab-snmp/internal/snmptest"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
	"github.com/hilather/go-lab-snmp/internal/usm"
)

func TestGETPublicSysDescr(t *testing.T) {
	s := startAgent(t, loadFull(t, nil))
	for _, ver := range []snmpwire.Version{snmpwire.VersionV1, snmpwire.VersionV2c} {
		m := getResp(t, s, ver, "public", sysDescr())
		p := m.RequestPDU()
		if p == nil || p.ErrorStatus != snmpwire.ErrorStatusNoError || len(p.VarBinds) != 1 {
			t.Fatalf("%s: %+v", ver, p)
		}
		if string(p.VarBinds[0].Value.Bytes) != "LabSNMP public-if" {
			t.Fatalf("%s value %q", ver, p.VarBinds[0].Value.Bytes)
		}
	}
}

func TestUnknownCommunitySilentDrop(t *testing.T) {
	var logBuf bytes.Buffer
	snap := loadFull(t, nil)
	st := snapshot.NewStore()
	st.InstallBootstrap(snap)
	s, err := New(Config{
		Addr:    "127.0.0.1:0",
		Store:   st,
		Clock:   snap.Clock,
		Metrics: observability.NewRegistry(),
		Logger:  observability.NewLogger(&logBuf, observability.LevelInfo),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	req := snmptest.MustEncodeGet(t, snmpwire.VersionV2c, "nope", 1, sysDescr())
	_, err = snmptest.Exchange(dst(s), req, 200*time.Millisecond)
	if err == nil {
		t.Fatal("unknown community must drop")
	}
	if s.AuthFail.Load() < 1 {
		t.Fatal("AuthFail counter")
	}
	if v, ok := s.metrics.Get(observability.MetricAuthFailTotal, map[string]string{"version": "v2c"}); !ok || v < 1 {
		t.Fatal("labsnmp_auth_fail_total")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_ = s.Shutdown(ctx)
	cancel()
	logs := logBuf.String()
	if !strings.Contains(logs, `"event":"snmp.pdu"`) || !strings.Contains(logs, `"event":"auth.failure"`) {
		t.Fatalf("catalog events missing: %s", logs)
	}
	if strings.Contains(logs, "nope") || strings.Contains(logs, "client_ip") {
		t.Fatal("secret/ip leaked into slog")
	}
}

func TestCommunityIsolation(t *testing.T) {
	s := startAgent(t, loadFull(t, nil))
	m := getResp(t, s, snmpwire.VersionV2c, "public", labPrivate())
	p := m.RequestPDU()
	if p == nil || p.VarBinds[0].Value.Type != snmpwire.TypeNoSuchObject {
		t.Fatalf("public must not see private-only OID: %+v", p)
	}
	priv := getResp(t, s, snmpwire.VersionV2c, "private", labPrivate())
	pp := priv.RequestPDU()
	if pp == nil || string(pp.VarBinds[0].Value.Bytes) != "private-horizon" {
		t.Fatalf("private GET: %+v", pp)
	}
}

func TestGETNEXTOrderLocked(t *testing.T) {
	s := startAgent(t, loadYAML(t, rwYAML, nil))
	cur := oid(1, 3)
	var got []string
	for i := 0; i < 16; i++ {
		req := snmptest.MustEncodeGetNext(t, snmpwire.VersionV2c, "public", int32(i+1), cur)
		m := snmptest.MustExchange(t, dst(s), req, 2*time.Second)
		p := m.RequestPDU()
		if p == nil || len(p.VarBinds) != 1 {
			t.Fatalf("%+v", p)
		}
		if p.VarBinds[0].Value.Type == snmpwire.TypeEndOfMibView {
			break
		}
		got = append(got, p.VarBinds[0].Name.String())
		cur = p.VarBinds[0].Name
	}
	want := []string{"1.3.6", "1.3.6.1", "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.2.2.1.8.1", "1.3.10"}
	if len(got) != len(want) {
		t.Fatalf("walk=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("walk=%v want=%v", got, want)
		}
	}
}

func TestUptimeFakeClock(t *testing.T) {
	clk := fakeClock()
	s := startAgent(t, loadYAML(t, rwYAML, clk))
	clk.Advance(time.Second)
	m := getResp(t, s, snmpwire.VersionV2c, "public", sysUpTime())
	p := m.RequestPDU()
	if p == nil || p.VarBinds[0].Value.Type != snmpwire.TypeTimeTicks || p.VarBinds[0].Value.Uint != 100 {
		t.Fatalf("uptime 1s: %+v", p)
	}
	s.Overlay().Set("rw", "1.3.6.1.2.1.1.3.0", mibtree.Value{Type: model.TypeTimeTicks, Unsigned: 999})
	m = getResp(t, s, snmpwire.VersionV2c, "public", sysUpTime())
	p = m.RequestPDU()
	if p.VarBinds[0].Value.Uint != 100 {
		t.Fatalf("overlay must not win uptime: %+v", p)
	}
}

func TestReadCommunityForbidsSet(t *testing.T) {
	s := startAgent(t, loadYAML(t, rwYAML, nil))
	req := snmptest.MustEncodeSet(t, snmpwire.VersionV2c, "public", 3, []snmpwire.VarBind{{
		Name:  ifOper(),
		Value: snmpwire.Int(2),
	}})
	m := snmptest.MustExchange(t, dst(s), req, 2*time.Second)
	p := m.RequestPDU()
	if p == nil || p.ErrorStatus != snmpwire.ErrorStatusNoAccess || p.ErrorIndex != 1 {
		t.Fatalf("read community SET: %+v", p)
	}
	if s.Overlay().Generation() != 0 {
		t.Fatalf("overlay gen=%d", s.Overlay().Generation())
	}
}

func TestTwoPhaseSET(t *testing.T) {
	s := startAgent(t, loadYAML(t, rwYAML, nil))
	bad := snmptest.MustEncodeSet(t, snmpwire.VersionV2c, "private", 4, []snmpwire.VarBind{
		{Name: ifOper(), Value: snmpwire.Int(2)},
		{Name: sysDescr(), Value: snmpwire.Int(1)},
	})
	m := snmptest.MustExchange(t, dst(s), bad, 2*time.Second)
	p := m.RequestPDU()
	if p == nil || p.ErrorStatus != snmpwire.ErrorStatusNotWritable || p.ErrorIndex != 2 {
		t.Fatalf("phase1: %+v", p)
	}
	if s.Overlay().Generation() != 0 {
		t.Fatal("failed SET must write nothing")
	}
	got := getResp(t, s, snmpwire.VersionV2c, "private", ifOper())
	if got.RequestPDU().VarBinds[0].Value.Int != 1 {
		t.Fatalf("bootstrap mutated: %+v", got.RequestPDU())
	}

	ok := snmptest.MustEncodeSet(t, snmpwire.VersionV2c, "private", 5, []snmpwire.VarBind{
		{Name: ifOper(), Value: snmpwire.Int(2)},
	})
	m = snmptest.MustExchange(t, dst(s), ok, 2*time.Second)
	p = m.RequestPDU()
	if p == nil || p.ErrorStatus != snmpwire.ErrorStatusNoError {
		t.Fatalf("phase2: %+v", p)
	}
	if s.Overlay().Generation() != 1 {
		t.Fatalf("gen=%d want 1", s.Overlay().Generation())
	}
	got = getResp(t, s, snmpwire.VersionV2c, "private", ifOper())
	if got.RequestPDU().VarBinds[0].Value.Int != 2 {
		t.Fatalf("GET after SET: %+v", got.RequestPDU())
	}
}

func TestV1GetMissingNoSuchName(t *testing.T) {
	s := startAgent(t, loadFull(t, nil))
	m := getResp(t, s, snmpwire.VersionV1, "public", labPrivate())
	p := m.RequestPDU()
	if p == nil || p.ErrorStatus != snmpwire.ErrorStatusNoSuchName || p.ErrorIndex != 1 {
		t.Fatalf("%+v", p)
	}
}

func TestV1GetErrorEchoesRequestBinds(t *testing.T) {
	s := startAgent(t, loadFull(t, nil))
	req := snmptest.MustEncodeGet(t, snmpwire.VersionV1, "public", 11, sysDescr(), labPrivate())
	m := snmptest.MustExchange(t, dst(s), req, 2*time.Second)
	p := m.RequestPDU()
	if p == nil || p.ErrorStatus != snmpwire.ErrorStatusNoSuchName || p.ErrorIndex != 2 {
		t.Fatalf("%+v", p)
	}
	if len(p.VarBinds) != 2 {
		t.Fatalf("varbinds %d", len(p.VarBinds))
	}
	if !p.VarBinds[0].Name.Equal(sysDescr()) || !p.VarBinds[1].Name.Equal(labPrivate()) {
		t.Fatalf("names %+v", p.VarBinds)
	}
	if p.VarBinds[0].Value.Type != snmpwire.TypeNull || p.VarBinds[1].Value.Type != snmpwire.TypeNull {
		t.Fatalf("v1 error must echo request NULLs: %+v", p.VarBinds)
	}
}

func TestGetBulk(t *testing.T) {
	s := startAgent(t, loadYAML(t, rwYAML, nil))
	req, err := snmptest.EncodeGetBulk("public", 9, 1, 2, oid(1, 3), oid(1, 3, 6))
	if err != nil {
		t.Fatal(err)
	}
	m := snmptest.MustExchange(t, dst(s), req, 2*time.Second)
	p := m.RequestPDU()
	if p == nil || len(p.VarBinds) != 3 {
		t.Fatalf("%+v", p)
	}
	got := []string{p.VarBinds[0].Name.String(), p.VarBinds[1].Name.String(), p.VarBinds[2].Name.String()}
	want := []string{"1.3.6", "1.3.6.1", "1.3.6.1.2.1.1.1.0"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("bulk %v want %v", got, want)
		}
	}
}

func TestAdmissionCIDRDrop(t *testing.T) {
	stYAML := `
apiVersion: labsnmp.dev/v1alpha1
kind: LabSNMP
metadata:
  name: deny
spec:
  admission:
    allowClientCidrs: ["10.99.42.0/24"]
  maps:
    - name: rw
      objects:
        - oid: "1.3.6.1.2.1.1.1.0"
          type: octetString
          value: "descr"
  communities:
    - name: public
      communityFile: testdata/secrets/snmp-public
      map: rw
`
	s := startAgent(t, loadYAML(t, stYAML, nil))
	req := snmptest.MustEncodeGet(t, snmpwire.VersionV2c, "public", 1, sysDescr())
	_, err := snmptest.Exchange(dst(s), req, 200*time.Millisecond)
	if err == nil {
		t.Fatal("CIDR miss must drop")
	}
	if s.Allowlist.Load() < 1 {
		t.Fatal("Allowlist counter")
	}
}

func TestUnmapIPv4MappedIntoLoopbackCIDR(t *testing.T) {
	mapped, err := netip.ParseAddr("::ffff:127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	p := netip.MustParsePrefix("127.0.0.0/8")
	if p.Contains(mapped) {
		t.Fatal("IPv4-mapped address must not match 127.0.0.0/8 without Unmap")
	}
	if !p.Contains(mapped.Unmap()) {
		t.Fatal("Unmap(::ffff:127.0.0.1) must match 127.0.0.0/8")
	}

	snap := loadFull(t, nil)
	st := snapshot.NewStore()
	st.InstallBootstrap(snap)
	s, err := New(Config{Addr: "127.0.0.1:0", Store: st})
	if err != nil {
		t.Fatal(err)
	}
	addr := &net.UDPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 9}
	ip := peerAddr(addr)
	if !ip.Is4() || ip.String() != "127.0.0.1" {
		t.Fatalf("peerAddr Unmap = %v", ip)
	}
	if !s.allowed(s.view(), ip) {
		t.Fatal("mapped loopback must be admitted to 127.0.0.0/8")
	}
}

func TestRateLimitDropsNthPlusOne(t *testing.T) {
	clk := fakeClock()
	stYAML := `
apiVersion: labsnmp.dev/v1alpha1
kind: LabSNMP
metadata:
  name: rate
spec:
  admission:
    allowClientCidrs: ["127.0.0.0/8", "::1/128"]
    maxDatagramsPerSec: 1
    maxDatagramsPerIP: 1
  maps:
    - name: rw
      objects:
        - oid: "1.3.6.1.2.1.1.1.0"
          type: octetString
          value: "descr"
  communities:
    - name: public
      communityFile: testdata/secrets/snmp-public
      map: rw
`
	s := startAgent(t, loadYAML(t, stYAML, clk))
	req := snmptest.MustEncodeGet(t, snmpwire.VersionV2c, "public", 1, sysDescr())
	_ = snmptest.MustExchange(t, dst(s), req, 2*time.Second)
	if s.Admission.Load() != 0 {
		t.Fatalf("first datagram Admission=%d", s.Admission.Load())
	}
	_, err := snmptest.Exchange(dst(s), req, 200*time.Millisecond)
	if err == nil {
		t.Fatal("second datagram in the same second must drop")
	}
	if s.Admission.Load() < 1 {
		t.Fatal("Admission counter")
	}
}

func TestManagementOffStillAnswers(t *testing.T) {
	s := startAgent(t, loadFull(t, nil))
	if !s.Ready() {
		t.Fatal("agent ready with management off")
	}
	_ = getResp(t, s, snmpwire.VersionV2c, "public", sysDescr())
}

func TestV3DiscoveryAndGET(t *testing.T) {
	clk := fakeClock()
	snap := loadYAML(t, rwYAML, clk)
	s := startAgent(t, snap)
	client, err := usm.New(usm.Config{
		EngineID:    snap.Engine.ID(),
		EngineBoots: 1,
		Clock:       clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := readTrimmed("testdata/secrets/snmp-alice-auth", repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	priv, err := readTrimmed("testdata/secrets/snmp-alice-priv", repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AddUser(usm.UserConfig{
		Name:           "alice",
		Level:          model.LevelAuthPriv,
		AuthProtocol:   model.AuthSHA256,
		AuthPassphrase: auth,
		PrivProtocol:   model.PrivAES128,
		PrivPassphrase: priv,
		Access:         model.AccessReadWrite,
		Map:            "rw",
	}); err != nil {
		t.Fatal(err)
	}

	disc := snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            1,
		MsgMaxSize:       65507,
		MsgFlags:         snmpwire.FlagReportable,
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		USM:              snmpwire.USMParameters{UserName: []byte("alice")},
		ScopedPDU: &snmpwire.ScopedPDU{
			PDU: snmpwire.PDU{
				Type:      snmpwire.PDUGet,
				RequestID: 1,
				VarBinds:  []snmpwire.VarBind{{Name: sysDescr(), Value: snmpwire.Null()}},
			},
		},
	}
	raw, err := snmpwire.Encode(disc)
	if err != nil {
		t.Fatal(err)
	}
	rep := snmptest.MustExchange(t, dst(s), raw, 2*time.Second)
	if p := rep.RequestPDU(); p == nil || p.Type != snmpwire.PDUReport {
		t.Fatalf("discovery: %+v", p)
	}

	user := client.User("alice")
	get := snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            2,
		MsgMaxSize:       65507,
		MsgFlags:         usm.Flags(model.LevelAuthPriv, true),
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		ScopedPDU: &snmpwire.ScopedPDU{
			PDU: snmpwire.PDU{
				Type:      snmpwire.PDUGet,
				RequestID: 2,
				VarBinds:  []snmpwire.VarBind{{Name: sysDescr(), Value: snmpwire.Null()}},
			},
		},
	}
	wrapped, err := client.Wrap(user, get)
	if err != nil {
		t.Fatal(err)
	}
	rawResp, err := snmptest.Exchange(dst(s), wrapped, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := snmpwire.Decode(rawResp)
	if err != nil {
		t.Fatal(err)
	}
	opened := snap.Engine.Open(rawResp, decoded)
	if opened.Incoming == nil {
		t.Fatalf("open response: drop=%v report=%d", opened.Drop, len(opened.Report))
	}
	p := opened.Incoming.Message.RequestPDU()
	if p == nil || p.Type != snmpwire.PDUResponse || string(p.VarBinds[0].Value.Bytes) != "descr" {
		t.Fatalf("v3 GET: %+v", p)
	}
}

func TestRebindMovesPacketConn(t *testing.T) {
	s := startAgent(t, loadFull(t, nil))
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
	m := getResp(t, s, snmpwire.VersionV2c, "public", sysDescr())
	p := m.RequestPDU()
	if p == nil || string(p.VarBinds[0].Value.Bytes) != "LabSNMP public-if" {
		t.Fatalf("%+v", p)
	}
	hold, err := net.ListenPacket("udp", old)
	if err != nil {
		t.Fatalf("old PacketConn must be closed: %v", err)
	}
	_ = hold.Close()
}

func TestRebindEmptyUnbinds(t *testing.T) {
	s := startAgent(t, loadFull(t, nil))
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

func TestRebindFailureKeepsOld(t *testing.T) {
	s := startAgent(t, loadFull(t, nil))
	old := s.Addr().String()
	hold, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	if err := s.Rebind(hold.LocalAddr().String()); err == nil {
		t.Fatal("expected listen failure")
	}
	if got := s.Addr().String(); got != old {
		t.Fatalf("failed Rebind moved %s -> %s", old, got)
	}
	m := getResp(t, s, snmpwire.VersionV2c, "public", sysDescr())
	p := m.RequestPDU()
	if p == nil || string(p.VarBinds[0].Value.Bytes) != "LabSNMP public-if" {
		t.Fatalf("old socket must keep serving: %+v", p)
	}
}
