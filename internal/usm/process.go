package usm

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"fmt"

	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
)

// Incoming is a successfully authenticated (and decrypted) v3 message.
type Incoming struct {
	User      *User
	Message   snmpwire.Message
	ScopedPDU snmpwire.ScopedPDU
}

// Outcome is the result of opening an incoming v3 datagram.
type Outcome struct {
	Incoming *Incoming
	Report   []byte // encoded authoritative Report, if any
	Drop     bool
}

// Open authenticates and decrypts a decoded SNMPv3 message destined to
// this authoritative engine (agent requests and INFORMs). raw must be
// the original datagram; HMAC is over those bytes.
func (e *Engine) Open(raw []byte, msg snmpwire.Message) Outcome {
	if msg.Version != snmpwire.VersionV3 || msg.MsgSecurityModel != snmpwire.SecurityModelUSM {
		return Outcome{Drop: true}
	}

	if len(msg.USM.EngineID) == 0 || !bytes.Equal(msg.USM.EngineID, e.ID()) {
		return e.fail(msg, OIDUnknownEngineIDs, func(s *Stats) *uint32 { return &s.UnknownEngineIDs }, nil, false, true)
	}

	u := e.User(string(msg.USM.UserName))
	if u == nil {
		return e.fail(msg, OIDUnknownUserNames, func(s *Stats) *uint32 { return &s.UnknownUserNames }, nil, false, msg.Reportable())
	}

	level := msgLevel(msg.MsgFlags)
	if level == "" || level != u.Level {
		return e.fail(msg, OIDUnsupportedSecLevels, func(s *Stats) *uint32 { return &s.UnsupportedSecLevels }, u, false, msg.Reportable())
	}

	if msg.Auth() {
		if err := e.verifyHMAC(raw, msg, u); err != nil {
			return e.fail(msg, OIDWrongDigests, func(s *Stats) *uint32 { return &s.WrongDigests }, u, false, msg.Reportable())
		}
		if !e.inTimeWindow(msg.USM.EngineBoots, msg.USM.EngineTime) {
			return e.fail(msg, OIDNotInTimeWindows, func(s *Stats) *uint32 { return &s.NotInTimeWindows }, u, true, msg.Reportable())
		}
	}

	scoped, ok := e.scoped(msg, u)
	if !ok {
		return e.fail(msg, OIDDecryptionErrors, func(s *Stats) *uint32 { return &s.DecryptionErrors }, u, false, msg.Reportable())
	}

	out := msg
	out.ScopedPDU = &scoped
	out.PDU = &scoped.PDU
	out.EncryptedPDU = nil
	return Outcome{Incoming: &Incoming{User: u, Message: out, ScopedPDU: scoped}}
}

func msgLevel(flags byte) string {
	auth := flags&snmpwire.FlagAuth != 0
	priv := flags&snmpwire.FlagPriv != 0
	switch {
	case priv && !auth:
		return ""
	case priv && auth:
		return model.LevelAuthPriv
	case auth:
		return model.LevelAuthNoPriv
	default:
		return model.LevelNoAuthNoPriv
	}
}

func (e *Engine) inTimeWindow(boots, etime int32) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	localBoots, localTime := e.bootsTimeLocked()
	if localBoots == maxEngineBoots {
		return false
	}
	if boots != localBoots {
		return false
	}
	d := int64(etime) - int64(localTime)
	if d < 0 {
		d = -d
	}
	return d <= TimeWindow
}

func (e *Engine) verifyHMAC(raw []byte, msg snmpwire.Message, u *User) error {
	want, err := macLen(u.AuthProtocol)
	if err != nil {
		return err
	}
	if len(msg.USM.AuthParams) != want {
		return fmt.Errorf("usm: authParams length")
	}
	off, n, err := authParamsOffset(raw)
	if err != nil || n != want {
		return fmt.Errorf("usm: authParams offset")
	}
	whole := bytes.Clone(raw)
	for i := 0; i < n; i++ {
		whole[off+i] = 0
	}
	mac, err := hmacMAC(u.AuthProtocol, u.authKey, whole)
	if err != nil {
		return err
	}
	if !hmac.Equal(mac, msg.USM.AuthParams) {
		return fmt.Errorf("usm: digest mismatch")
	}
	return nil
}

func (e *Engine) scoped(msg snmpwire.Message, u *User) (snmpwire.ScopedPDU, bool) {
	if !msg.Priv() {
		if msg.ScopedPDU == nil {
			return snmpwire.ScopedPDU{}, false
		}
		return *msg.ScopedPDU, true
	}
	plain, err := decrypt(u.PrivProtocol, u.privKey, msg.USM.EngineBoots, msg.USM.EngineTime, msg.USM.PrivParams, msg.EncryptedPDU)
	if err != nil {
		return snmpwire.ScopedPDU{}, false
	}
	sp, err := snmpwire.DecodeScopedPDU(plain)
	if err != nil {
		return snmpwire.ScopedPDU{}, false
	}
	return sp, true
}

func (e *Engine) fail(req snmpwire.Message, oid snmpwire.OID, counter func(*Stats) *uint32, user *User, auth, always bool) Outcome {
	e.mu.Lock()
	c := counter(&e.stats)
	*c++
	n := *c
	e.mu.Unlock()

	reportable := always || req.Reportable()
	if !reportable {
		return Outcome{Drop: true}
	}
	wire, err := e.encodeReport(req, oid, n, user, auth)
	if err != nil {
		return Outcome{Drop: true}
	}
	return Outcome{Report: wire}
}

func (e *Engine) encodeReport(req snmpwire.Message, oid snmpwire.OID, value uint32, user *User, auth bool) ([]byte, error) {
	flags := byte(0)
	if auth && user != nil && user.AuthProtocol != "" {
		flags = snmpwire.FlagAuth
	}
	max := req.MsgMaxSize
	if max <= 0 {
		max = int32(snmpwire.DefaultMaxMessageBytes)
	}
	msg := snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            req.MsgID,
		MsgMaxSize:       max,
		MsgFlags:         flags,
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		USM: snmpwire.USMParameters{
			UserName: bytes.Clone(req.USM.UserName),
		},
		ScopedPDU: &snmpwire.ScopedPDU{
			PDU: snmpwire.PDU{
				Type:      snmpwire.PDUReport,
				RequestID: requestID(req),
				VarBinds: []snmpwire.VarBind{{
					Name:  append(snmpwire.OID(nil), oid...),
					Value: snmpwire.Counter32Val(value),
				}},
			},
		},
	}
	return e.Wrap(user, msg)
}

func requestID(msg snmpwire.Message) int32 {
	if msg.ScopedPDU != nil {
		return msg.ScopedPDU.PDU.RequestID
	}
	if msg.PDU != nil {
		return msg.PDU.RequestID
	}
	return 0
}

// Wrap applies authoritative engineID/boots/time and optional auth/priv.
// msg.MsgFlags select the services; user must supply matching keys.
func (e *Engine) Wrap(user *User, msg snmpwire.Message) ([]byte, error) {
	boots, etime := e.BootsTime()
	msg.Version = snmpwire.VersionV3
	msg.MsgSecurityModel = snmpwire.SecurityModelUSM
	msg.USM.EngineID = e.ID()
	msg.USM.EngineBoots = boots
	msg.USM.EngineTime = etime
	if user != nil {
		msg.USM.UserName = []byte(user.Name)
	}
	if msg.ScopedPDU != nil && len(msg.ScopedPDU.ContextEngineID) == 0 {
		msg.ScopedPDU.ContextEngineID = e.ID()
	}
	if msg.MsgMaxSize <= 0 {
		msg.MsgMaxSize = int32(snmpwire.DefaultMaxMessageBytes)
	}

	if msg.Priv() {
		if user == nil || user.privKey == nil {
			return nil, fmt.Errorf("usm: privacy requires a priv user")
		}
		if msg.ScopedPDU == nil {
			return nil, fmt.Errorf("usm: privacy requires a scopedPDU")
		}
		plain, err := snmpwire.EncodeScopedPDU(*msg.ScopedPDU)
		if err != nil {
			return nil, err
		}
		salt := e.newSalt(user.PrivProtocol == model.PrivDES, boots)
		ct, err := encrypt(user.PrivProtocol, user.privKey, boots, etime, salt, plain)
		if err != nil {
			return nil, err
		}
		msg.EncryptedPDU = ct
		msg.USM.PrivParams = salt
		msg.ScopedPDU = nil
		msg.PDU = nil
	} else {
		msg.USM.PrivParams = nil
		msg.EncryptedPDU = nil
	}

	if msg.Auth() {
		if user == nil || user.authKey == nil {
			return nil, fmt.Errorf("usm: authentication requires an auth user")
		}
		n, err := macLen(user.AuthProtocol)
		if err != nil {
			return nil, err
		}
		msg.USM.AuthParams = make([]byte, n)
		encoded, err := snmpwire.Encode(msg)
		if err != nil {
			return nil, err
		}
		off, got, err := authParamsOffset(encoded)
		if err != nil || got != n {
			return nil, fmt.Errorf("usm: encoded authParams")
		}
		mac, err := hmacMAC(user.AuthProtocol, user.authKey, encoded)
		if err != nil {
			return nil, err
		}
		copy(encoded[off:off+n], mac)
		return encoded, nil
	}

	msg.USM.AuthParams = nil
	return snmpwire.Encode(msg)
}

// Reply encodes a Response/Report PDU at the incoming user's security level.
func (e *Engine) Reply(in *Incoming, pdu snmpwire.PDU) ([]byte, error) {
	if in == nil || in.User == nil {
		return nil, fmt.Errorf("usm: nil incoming")
	}
	max := in.Message.MsgMaxSize
	if max <= 0 {
		max = int32(snmpwire.DefaultMaxMessageBytes)
	}
	msg := snmpwire.Message{
		Version:          snmpwire.VersionV3,
		MsgID:            in.Message.MsgID,
		MsgMaxSize:       max,
		MsgFlags:         Flags(in.User.Level, false),
		MsgSecurityModel: snmpwire.SecurityModelUSM,
		ScopedPDU: &snmpwire.ScopedPDU{
			ContextEngineID: bytes.Clone(in.ScopedPDU.ContextEngineID),
			ContextName:     bytes.Clone(in.ScopedPDU.ContextName),
			PDU:             pdu,
		},
	}
	return e.Wrap(in.User, msg)
}

func (e *Engine) newSalt(des bool, boots int32) []byte {
	e.mu.Lock()
	e.salt++
	n := e.salt
	e.mu.Unlock()
	s := make([]byte, 8)
	if des {
		binary.BigEndian.PutUint32(s[:4], uint32(boots))
		binary.BigEndian.PutUint32(s[4:], uint32(n))
	} else {
		binary.BigEndian.PutUint64(s, n)
	}
	return s
}

type cursor struct {
	b   []byte
	i   int
	end int
}

func authParamsOffset(whole []byte) (int, int, error) {
	c := cursor{b: whole, end: len(whole)}
	if err := c.enter(0x30); err != nil {
		return 0, 0, err
	}
	if _, err := c.skip(); err != nil { // version
		return 0, 0, err
	}
	if _, err := c.skip(); err != nil { // header
		return 0, 0, err
	}
	tag, off, n, err := c.tlv()
	if err != nil || tag != 0x04 {
		return 0, 0, fmt.Errorf("usm: securityParameters")
	}
	inner := cursor{b: whole, i: off, end: off + n}
	if err := inner.enter(0x30); err != nil {
		return 0, 0, err
	}
	for i := 0; i < 4; i++ {
		if _, err := inner.skip(); err != nil {
			return 0, 0, err
		}
	}
	tag, aoff, an, err := inner.tlv()
	if err != nil || tag != 0x04 {
		return 0, 0, fmt.Errorf("usm: authParams")
	}
	return aoff, an, nil
}

func (c *cursor) enter(want byte) error {
	tag, off, n, err := c.tlv()
	if err != nil {
		return err
	}
	if tag != want {
		return fmt.Errorf("usm: expected tag 0x%02x got 0x%02x", want, tag)
	}
	c.i = off
	c.end = off + n
	return nil
}

func (c *cursor) skip() (byte, error) {
	tag, _, _, err := c.tlv()
	return tag, err
}

func (c *cursor) tlv() (tag byte, contentOff, contentLen int, err error) {
	if c.i >= c.end {
		return 0, 0, 0, fmt.Errorf("usm: truncated BER")
	}
	tag = c.b[c.i]
	c.i++
	n, err := c.readLen()
	if err != nil {
		return 0, 0, 0, err
	}
	if n < 0 || c.i+n > c.end {
		return 0, 0, 0, fmt.Errorf("usm: truncated BER")
	}
	contentOff = c.i
	contentLen = n
	c.i += n
	return tag, contentOff, contentLen, nil
}

func (c *cursor) readLen() (int, error) {
	if c.i >= c.end {
		return 0, fmt.Errorf("usm: truncated BER")
	}
	b := c.b[c.i]
	c.i++
	if b == 0x80 {
		return 0, fmt.Errorf("usm: indefinite length")
	}
	if b < 0x80 {
		return int(b), nil
	}
	nb := int(b & 0x7f)
	if nb == 0 || nb > 4 {
		return 0, fmt.Errorf("usm: invalid length form")
	}
	if c.i+nb > c.end {
		return 0, fmt.Errorf("usm: truncated BER")
	}
	var v int
	for i := 0; i < nb; i++ {
		v = (v << 8) | int(c.b[c.i])
		c.i++
	}
	return v, nil
}
