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

// MustExchange fails the test if the agent does not answer.
func MustExchange(t testing.TB, dst string, req []byte, timeout time.Duration) snmpwire.Message {
	t.Helper()
	raw, err := Exchange(dst, req, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return MustDecode(t, raw)
}
