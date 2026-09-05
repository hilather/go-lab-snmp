package snmptest

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/snmpwire"
)

// Exchange sends req to dst over UDP and returns one response datagram.
func Exchange(dst string, req []byte, timeout time.Duration) ([]byte, error) {
	c, err := net.Dial("udp", dst)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 64<<10)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, nil
}

// EncodeGet builds a community Get PDU.
func EncodeGet(ver snmpwire.Version, community string, reqID int32, oids ...snmpwire.OID) ([]byte, error) {
	return encodeCommunity(ver, community, snmpwire.PDUGet, reqID, 0, 0, oids, nil)
}

// EncodeGetNext builds a community GetNext PDU.
func EncodeGetNext(ver snmpwire.Version, community string, reqID int32, oids ...snmpwire.OID) ([]byte, error) {
	return encodeCommunity(ver, community, snmpwire.PDUGetNext, reqID, 0, 0, oids, nil)
}

// EncodeGetBulk builds a community GetBulk PDU.
func EncodeGetBulk(community string, reqID, nonRepeaters, maxRepetitions int32, oids ...snmpwire.OID) ([]byte, error) {
	return encodeCommunity(snmpwire.VersionV2c, community, snmpwire.PDUGetBulk, reqID, nonRepeaters, maxRepetitions, oids, nil)
}

// EncodeSet builds a community Set PDU.
func EncodeSet(ver snmpwire.Version, community string, reqID int32, binds []snmpwire.VarBind) ([]byte, error) {
	oids := make([]snmpwire.OID, len(binds))
	vals := make([]snmpwire.Value, len(binds))
	for i, b := range binds {
		oids[i] = b.Name
		vals[i] = b.Value
	}
	return encodeCommunity(ver, community, snmpwire.PDUSet, reqID, 0, 0, oids, vals)
}

func encodeCommunity(ver snmpwire.Version, community string, pdu snmpwire.PDUType, reqID, non, max int32, oids []snmpwire.OID, vals []snmpwire.Value) ([]byte, error) {
	vbs := make([]snmpwire.VarBind, len(oids))
	for i, oid := range oids {
		v := snmpwire.Null()
		if vals != nil {
			v = vals[i]
		}
		vbs[i] = snmpwire.VarBind{Name: oid, Value: v}
	}
	p := snmpwire.PDU{Type: pdu, RequestID: reqID, VarBinds: vbs}
	if pdu == snmpwire.PDUGetBulk {
		p.NonRepeaters = non
		p.MaxRepetitions = max
	}
	b, err := snmpwire.Encode(snmpwire.Message{
		Version:   ver,
		Community: []byte(community),
		PDU:       &p,
	})
	if err != nil {
		return nil, fmt.Errorf("snmptest: encode: %w", err)
	}
	return b, nil
}

// MustEncodeGet fails the test on encode error.
func MustEncodeGet(t testing.TB, ver snmpwire.Version, community string, reqID int32, oids ...snmpwire.OID) []byte {
	t.Helper()
	b, err := EncodeGet(ver, community, reqID, oids...)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// MustEncodeGetNext fails the test on encode error.
func MustEncodeGetNext(t testing.TB, ver snmpwire.Version, community string, reqID int32, oids ...snmpwire.OID) []byte {
	t.Helper()
	b, err := EncodeGetNext(ver, community, reqID, oids...)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// MustEncodeSet fails the test on encode error.
func MustEncodeSet(t testing.TB, ver snmpwire.Version, community string, reqID int32, binds []snmpwire.VarBind) []byte {
	t.Helper()
	b, err := EncodeSet(ver, community, reqID, binds)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// EncodeCommunity serializes a v1/v2c PDU.
func EncodeCommunity(ver snmpwire.Version, community string, pdu snmpwire.PDU) ([]byte, error) {
	return snmpwire.Encode(snmpwire.Message{
		Version:   ver,
		Community: []byte(community),
		PDU:       &pdu,
	})
}

// EncodeTrapV2 builds a community SNMPv2-Trap.
func EncodeTrapV2(community string, reqID int32, trapOID snmpwire.OID, extra ...snmpwire.VarBind) ([]byte, error) {
	return EncodeCommunity(snmpwire.VersionV2c, community, TrapV2PDU(reqID, trapOID, extra...))
}

// EncodeInform builds a community INFORM.
func EncodeInform(community string, reqID int32, trapOID snmpwire.OID, extra ...snmpwire.VarBind) ([]byte, error) {
	p := TrapV2PDU(reqID, trapOID, extra...)
	p.Type = snmpwire.PDUInform
	return EncodeCommunity(snmpwire.VersionV2c, community, p)
}

// EncodeTrapV1 builds a community TRAPv1.
func EncodeTrapV1(community string, pdu snmpwire.PDU) ([]byte, error) {
	pdu.Type = snmpwire.PDUTrapV1
	return EncodeCommunity(snmpwire.VersionV1, community, pdu)
}

// TrapV2PDU is the SNMPv2-Trap/INFORM varbind prefix (sysUpTime, snmpTrapOID).
func TrapV2PDU(reqID int32, trapOID snmpwire.OID, extra ...snmpwire.VarBind) snmpwire.PDU {
	vbs := []snmpwire.VarBind{
		{Name: snmpwire.OID{1, 3, 6, 1, 2, 1, 1, 3, 0}, Value: snmpwire.TimeTicksVal(1)},
		{Name: snmpwire.OID{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}, Value: snmpwire.ObjectIdentifier(trapOID)},
	}
	vbs = append(vbs, extra...)
	return snmpwire.PDU{Type: snmpwire.PDUTrapV2, RequestID: reqID, VarBinds: vbs}
}

// Send writes req to dst and does not wait for a reply.
func Send(dst string, req []byte) error {
	c, err := net.Dial("udp", dst)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	_, err = c.Write(req)
	return err
}

// MustSend fails the test on send error.
func MustSend(t testing.TB, dst string, req []byte) {
	t.Helper()
	if err := Send(dst, req); err != nil {
		t.Fatal(err)
	}
}

// MustEncodeInform fails the test on encode error.
func MustEncodeInform(t testing.TB, community string, reqID int32, trapOID snmpwire.OID) []byte {
	t.Helper()
	b, err := EncodeInform(community, reqID, trapOID)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// MustEncodeTrapV2 fails the test on encode error.
func MustEncodeTrapV2(t testing.TB, community string, reqID int32, trapOID snmpwire.OID) []byte {
	t.Helper()
	b, err := EncodeTrapV2(community, reqID, trapOID)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// MustExchange fails the test if the agent does not answer.
func MustExchange(t testing.TB, dst string, req []byte, timeout time.Duration) snmpwire.Message {
	t.Helper()
	raw, err := Exchange(dst, req, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return MustDecode(t, raw)
}
