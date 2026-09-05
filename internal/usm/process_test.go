package usm

import (
	"bytes"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
	"github.com/hilather/go-lab-snmp/internal/testutil"
)

func sysDescr() snmpwire.OID { return snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0} }

func getPDU(reqID int32) snmpwire.PDU {
	return snmpwire.PDU{
		Type:      snmpwire.PDUGet,
		RequestID: reqID,
		VarBinds: []snmpwire.VarBind{{
			Name:  sysDescr(),
			Value: snmpwire.Null(),
		}},
	}
}

func discoveryMsg(user string, reqID int32) snmpwire.Message {
	return snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            reqID,
		MsgMaxSize:       65507,
		MsgFlags:         snmpwire.FlagReportable,
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		USM:              snmpwire.USMParameters{UserName: []byte(user)},
		ScopedPDU: &snmpwire.ScopedPDU{
			PDU: getPDU(reqID),
		},
	}
}

func encodeMsg(t *testing.T, m snmpwire.Message) []byte {
	t.Helper()
	b, err := snmpwire.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func decodeReport(t *testing.T, b []byte) snmpwire.Message {
	t.Helper()
	if b == nil {
		t.Fatal("missing Report")
	}
	m, err := snmpwire.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	p := m.RequestPDU()
	if p == nil || p.Type != snmpwire.PDUReport {
		t.Fatalf("want Report got %+v", p)
	}
	return m
}

func reportOID(m snmpwire.Message) snmpwire.OID {
	p := m.RequestPDU()
	if p == nil || len(p.VarBinds) == 0 {
		return nil
	}
	return p.VarBinds[0].Name
}

func TestDiscoveryEmptyEngineID(t *testing.T) {
	clk := testutil.NewFakeClock(time.Unix(1_700_000_000, 0))
	e := mustEngine(t, clk)
	clk.Advance(42 * time.Second)
	req := discoveryMsg("alice", 9)
	raw := encodeMsg(t, req)
	out := e.Open(raw, req)
	if out.Drop || out.Incoming != nil {
		t.Fatalf("drop=%v incoming=%v", out.Drop, out.Incoming != nil)
	}
	got := decodeReport(t, out.Report)
	if got.Auth() || got.Priv() {
		t.Fatalf("discovery Report must be unauthenticated flags=%02x", got.MsgFlags)
	}
	if !bytes.Equal(got.USM.EngineID, e.ID()) {
		t.Fatalf("engineID %x", got.USM.EngineID)
	}
	if got.USM.EngineBoots != 1 || got.USM.EngineTime != 42 {
		t.Fatalf("boots=%d time=%d", got.USM.EngineBoots, got.USM.EngineTime)
	}
	if !reportOID(got).Equal(OIDUnknownEngineIDs) {
		t.Fatalf("oid %s", reportOID(got))
	}
	if got.MsgID != 9 || got.RequestPDU().RequestID != 9 {
		t.Fatalf("ids msg=%d req=%d", got.MsgID, got.RequestPDU().RequestID)
	}
	if e.Stats().UnknownEngineIDs != 1 {
		t.Fatalf("stats %+v", e.Stats())
	}
}

func TestDiscoveryEmptyUserName(t *testing.T) {
	e := mustEngine(t, nil)
	req := discoveryMsg("", 1)
	raw := encodeMsg(t, req)
	out := e.Open(raw, req)
	got := decodeReport(t, out.Report)
	if !reportOID(got).Equal(OIDUnknownEngineIDs) {
		t.Fatalf("oid %s", reportOID(got))
	}
	if len(got.USM.UserName) != 0 {
		t.Fatalf("userName %q", got.USM.UserName)
	}
}

func TestDiscoveryUnknownEngineID(t *testing.T) {
	e := mustEngine(t, nil)
	req := discoveryMsg("alice", 3)
	req.USM.EngineID = []byte{0x80, 0x00, 0x00, 0x00, 0xff}
	raw := encodeMsg(t, req)
	out := e.Open(raw, req)
	got := decodeReport(t, out.Report)
	if !reportOID(got).Equal(OIDUnknownEngineIDs) {
		t.Fatalf("oid %s", reportOID(got))
	}
	if !bytes.Equal(got.USM.EngineID, e.ID()) {
		t.Fatal("report must carry this engineID")
	}
}

func TestUnknownUser(t *testing.T) {
	e := mustEngine(t, nil)
	if err := e.AddUser(UserConfig{Name: "alice", Level: model.LevelNoAuthNoPriv}); err != nil {
		t.Fatal(err)
	}
	req := discoveryMsg("bob", 4)
	req.USM.EngineID = e.ID()
	raw := encodeMsg(t, req)
	out := e.Open(raw, req)
	got := decodeReport(t, out.Report)
	if !reportOID(got).Equal(OIDUnknownUserNames) {
		t.Fatalf("oid %s", reportOID(got))
	}
	if got.Auth() {
		t.Fatal("unknownUserNames Report is unauthenticated")
	}
}

func TestRoundTripLevels(t *testing.T) {
	pass := []byte("maplesyrup")
	priv := []byte("priv-pass")
	cases := []UserConfig{
		{Name: "none", Level: model.LevelNoAuthNoPriv},
		{Name: "md5", Level: model.LevelAuthNoPriv, AuthProtocol: model.AuthMD5, AuthPassphrase: pass},
		{Name: "sha1", Level: model.LevelAuthNoPriv, AuthProtocol: model.AuthSHA1, AuthPassphrase: pass},
		{Name: "sha256", Level: model.LevelAuthNoPriv, AuthProtocol: model.AuthSHA256, AuthPassphrase: pass},
		{Name: "md5des", Level: model.LevelAuthPriv, AuthProtocol: model.AuthMD5, AuthPassphrase: pass, PrivProtocol: model.PrivDES, PrivPassphrase: priv},
		{Name: "sha1des", Level: model.LevelAuthPriv, AuthProtocol: model.AuthSHA1, AuthPassphrase: pass, PrivProtocol: model.PrivDES, PrivPassphrase: priv},
		{Name: "sha256aes", Level: model.LevelAuthPriv, AuthProtocol: model.AuthSHA256, AuthPassphrase: pass, PrivProtocol: model.PrivAES128, PrivPassphrase: priv},
		{Name: "sha1aes", Level: model.LevelAuthPriv, AuthProtocol: model.AuthSHA1, AuthPassphrase: pass, PrivProtocol: model.PrivAES128, PrivPassphrase: priv},
	}
	for _, cfg := range cases {
		t.Run(cfg.Name, func(t *testing.T) {
			e := mustEngine(t, nil)
			if err := e.AddUser(cfg); err != nil {
				t.Fatal(err)
			}
			u := e.User(cfg.Name)
			scoped := snmpwire.ScopedPDU{PDU: getPDU(77)}
			msg := snmpwire.Message{
				Version:          snmpwire.VersionV3,
				MsgID:            77,
				MsgMaxSize:       65507,
				MsgFlags:         Flags(cfg.Level, true),
				MsgSecurityModel: snmpwire.SecurityModelUSM,
				ScopedPDU:        &scoped,
			}
			wire, err := e.Wrap(u, msg)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := snmpwire.Decode(wire)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Level == model.LevelAuthPriv {
				if decoded.ScopedPDU != nil || len(decoded.EncryptedPDU) == 0 {
					t.Fatal("WIRE must leave ciphertext as OCTET STRING")
				}
			}
			out := e.Open(wire, decoded)
			if out.Drop || out.Report != nil || out.Incoming == nil {
				t.Fatalf("outcome drop=%v report=%v", out.Drop, out.Report != nil)
			}
			got := out.Incoming.ScopedPDU.PDU
			if got.Type != snmpwire.PDUGet || got.RequestID != 77 {
				t.Fatalf("pdu %+v", got)
			}
			if !got.VarBinds[0].Name.Equal(sysDescr()) {
				t.Fatalf("oid %s", got.VarBinds[0].Name)
			}

			resp, err := e.Reply(out.Incoming, snmpwire.PDU{
				Type:      snmpwire.PDUResponse,
				RequestID: 77,
				VarBinds: []snmpwire.VarBind{{
					Name:  sysDescr(),
					Value: snmpwire.OctetString([]byte("LabSNMP")),
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			rm, err := snmpwire.Decode(resp)
			if err != nil {
				t.Fatal(err)
			}
			rout := e.Open(resp, rm)
			if rout.Incoming == nil {
				t.Fatalf("reply not openable report=%v", rout.Report != nil)
			}
			if rout.Incoming.ScopedPDU.PDU.Type != snmpwire.PDUResponse {
				t.Fatalf("reply pdu %s", rout.Incoming.ScopedPDU.PDU.Type)
			}
		})
	}
}

func TestWrongPassphraseReportNotPanic(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("panic: %v", rec)
		}
	}()
	good := mustEngine(t, nil)
	bad := mustEngine(t, nil)
	pass := []byte("maplesyrup")
	if err := good.AddUser(UserConfig{
		Name: "alice", Level: model.LevelAuthNoPriv,
		AuthProtocol: model.AuthSHA256, AuthPassphrase: pass,
	}); err != nil {
		t.Fatal(err)
	}
	if err := bad.AddUser(UserConfig{
		Name: "alice", Level: model.LevelAuthNoPriv,
		AuthProtocol: model.AuthSHA256, AuthPassphrase: []byte("wrong-passphrase"),
	}); err != nil {
		t.Fatal(err)
	}
	u := good.User("alice")
	msg := snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            1,
		MsgMaxSize:       65507,
		MsgFlags:         Flags(model.LevelAuthNoPriv, true),
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		ScopedPDU:        &snmpwire.ScopedPDU{PDU: getPDU(1)},
	}
	wire, err := good.Wrap(u, msg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := snmpwire.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	out := bad.Open(wire, decoded)
	got := decodeReport(t, out.Report)
	if !reportOID(got).Equal(OIDWrongDigests) {
		t.Fatalf("oid %s", reportOID(got))
	}
}

func TestWrongPrivPassphrase(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("panic: %v", rec)
		}
	}()
	auth := []byte("maplesyrup")
	good := mustEngine(t, nil)
	bad := mustEngine(t, nil)
	cfg := func(priv []byte) UserConfig {
		return UserConfig{
			Name: "alice", Level: model.LevelAuthPriv,
			AuthProtocol: model.AuthSHA256, AuthPassphrase: auth,
			PrivProtocol: model.PrivAES128, PrivPassphrase: priv,
		}
	}
	if err := good.AddUser(cfg([]byte("priv-pass-1"))); err != nil {
		t.Fatal(err)
	}
	if err := bad.AddUser(cfg([]byte("priv-pass-2"))); err != nil {
		t.Fatal(err)
	}
	msg := snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            2,
		MsgMaxSize:       65507,
		MsgFlags:         Flags(model.LevelAuthPriv, true),
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		ScopedPDU:        &snmpwire.ScopedPDU{PDU: getPDU(2)},
	}
	wire, err := good.Wrap(good.User("alice"), msg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := snmpwire.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	out := bad.Open(wire, decoded)
	got := decodeReport(t, out.Report)
	if !reportOID(got).Equal(OIDDecryptionErrors) {
		t.Fatalf("oid %s", reportOID(got))
	}
}

func TestNotInTimeWindow(t *testing.T) {
	clk := testutil.NewFakeClock(time.Unix(5000, 0))
	e := mustEngine(t, clk)
	if err := e.AddUser(UserConfig{
		Name: "alice", Level: model.LevelAuthNoPriv,
		AuthProtocol: model.AuthSHA1, AuthPassphrase: []byte("maplesyrup"),
	}); err != nil {
		t.Fatal(err)
	}
	msg := snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            5,
		MsgMaxSize:       65507,
		MsgFlags:         Flags(model.LevelAuthNoPriv, true),
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		ScopedPDU:        &snmpwire.ScopedPDU{PDU: getPDU(5)},
	}
	wire, err := e.Wrap(e.User("alice"), msg)
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(151 * time.Second)
	decoded, err := snmpwire.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	out := e.Open(wire, decoded)
	got := decodeReport(t, out.Report)
	if !reportOID(got).Equal(OIDNotInTimeWindows) {
		t.Fatalf("oid %s", reportOID(got))
	}
	if !got.Auth() || got.Priv() {
		t.Fatalf("notInTimeWindows Report is authNoPriv flags=%02x", got.MsgFlags)
	}
	if got.USM.EngineTime != 151 {
		t.Fatalf("report time %d", got.USM.EngineTime)
	}

	clk.Set(time.Unix(5000, 0))
	e2 := mustEngine(t, clk)
	if err := e2.AddUser(UserConfig{
		Name: "alice", Level: model.LevelAuthNoPriv,
		AuthProtocol: model.AuthSHA1, AuthPassphrase: []byte("maplesyrup"),
	}); err != nil {
		t.Fatal(err)
	}
	wire, err = e2.Wrap(e2.User("alice"), msg)
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(150 * time.Second)
	decoded, err = snmpwire.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	out = e2.Open(wire, decoded)
	if out.Incoming == nil {
		t.Fatal("150s is still inside the window")
	}
}

func TestBootsMismatch(t *testing.T) {
	id, err := ParseEngineID("80000000046c6162736e6d70aabbccdd")
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{EngineID: id, EngineBoots: 1})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{EngineID: id, EngineBoots: 2})
	if err != nil {
		t.Fatal(err)
	}
	cfg := UserConfig{
		Name: "alice", Level: model.LevelAuthNoPriv,
		AuthProtocol: model.AuthMD5, AuthPassphrase: []byte("maplesyrup"),
	}
	if err := a.AddUser(cfg); err != nil {
		t.Fatal(err)
	}
	if err := b.AddUser(cfg); err != nil {
		t.Fatal(err)
	}
	msg := snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            6,
		MsgMaxSize:       65507,
		MsgFlags:         Flags(model.LevelAuthNoPriv, true),
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		ScopedPDU:        &snmpwire.ScopedPDU{PDU: getPDU(6)},
	}
	wire, err := a.Wrap(a.User("alice"), msg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := snmpwire.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	out := b.Open(wire, decoded)
	got := decodeReport(t, out.Report)
	if !reportOID(got).Equal(OIDNotInTimeWindows) {
		t.Fatalf("oid %s", reportOID(got))
	}
}

func TestUnsupportedSecLevel(t *testing.T) {
	e := mustEngine(t, nil)
	if err := e.AddUser(UserConfig{
		Name: "alice", Level: model.LevelAuthPriv,
		AuthProtocol: model.AuthMD5, AuthPassphrase: []byte("maplesyrup"),
		PrivProtocol: model.PrivDES, PrivPassphrase: []byte("priv-pass"),
	}); err != nil {
		t.Fatal(err)
	}
	req := discoveryMsg("alice", 8)
	req.USM.EngineID = e.ID()
	raw := encodeMsg(t, req)
	out := e.Open(raw, req)
	got := decodeReport(t, out.Report)
	if !reportOID(got).Equal(OIDUnsupportedSecLevels) {
		t.Fatalf("oid %s", reportOID(got))
	}
}

func TestAliceAuthPrivFromTestdata(t *testing.T) {
	e := mustEngine(t, nil)
	auth, priv := aliceSecrets(t)
	if err := e.AddUser(UserConfig{
		Name: "alice", Level: model.LevelAuthPriv,
		AuthProtocol: model.AuthSHA256, AuthPassphrase: auth,
		PrivProtocol: model.PrivAES128, PrivPassphrase: priv,
		Access: model.AccessReadWrite, Map: "private-if",
	}); err != nil {
		t.Fatal(err)
	}
	msg := snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            11,
		MsgMaxSize:       65507,
		MsgFlags:         Flags(model.LevelAuthPriv, true),
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		ScopedPDU:        &snmpwire.ScopedPDU{PDU: getPDU(11)},
	}
	wire, err := e.Wrap(e.User("alice"), msg)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := snmpwire.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	out := e.Open(wire, decoded)
	if out.Incoming == nil || out.Incoming.User.Name != "alice" {
		t.Fatalf("alice GET failed report=%v", out.Report != nil)
	}
}

func TestNonUSMDropped(t *testing.T) {
	e := mustEngine(t, nil)
	out := e.Open(nil, snmpwire.Message{Version: snmpwire.VersionV2c})
	if !out.Drop {
		t.Fatal("v2c must drop")
	}
}
