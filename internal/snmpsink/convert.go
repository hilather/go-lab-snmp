package snmpsink

import (
	"strconv"
	"time"

	"github.com/hilather/go-lab-snmp/internal/snmpwire"
	"github.com/hilather/go-lab-snmp/internal/store"
)

var (
	oidSnmpTrapOID        = snmpwire.OID{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	oidSnmpTrapEnterprise = snmpwire.OID{1, 3, 6, 1, 6, 3, 1, 1, 4, 3, 0}
	oidSnmpTraps          = snmpwire.OID{1, 3, 6, 1, 6, 3, 1, 1, 5}
)

func recordFrom(msg snmpwire.Message, community, user, remote, warning string, now time.Time) store.TrapRecord {
	rec := store.TrapRecord{
		ReceivedAt:   now,
		Version:      versionLabel(msg.Version),
		Community:    community,
		User:         user,
		RemoteAddr:   remote,
		ParseWarning: warning,
	}
	p := msg.RequestPDU()
	if p == nil {
		if warning == "" {
			rec.ParseWarning = "missing PDU"
		}
		return rec
	}
	rec.PDUType = p.Type.String()
	rec.VarBinds = convertVarBinds(p.VarBinds)
	switch p.Type {
	case snmpwire.PDUTrapV1:
		rec.Enterprise, rec.NotificationOID = notificationFromV1(*p)
	default:
		rec.Enterprise, rec.NotificationOID = notificationFromV2(*p)
	}
	if rec.NotificationOID == "" && rec.ParseWarning == "" {
		rec.ParseWarning = "missing notification OID"
	}
	return rec
}

func notificationFromV1(p snmpwire.PDU) (enterprise, notif string) {
	enterprise = p.Enterprise.String()
	if p.GenericTrap == snmpwire.TrapEnterpriseSpecific {
		if enterprise == "" {
			return "", ""
		}
		return enterprise, enterprise + ".0." + strconv.FormatInt(int64(p.SpecificTrap), 10)
	}
	return enterprise, oidSnmpTraps.String() + "." + strconv.FormatInt(int64(p.GenericTrap+1), 10)
}

func notificationFromV2(p snmpwire.PDU) (enterprise, notif string) {
	for _, vb := range p.VarBinds {
		if vb.Name.Equal(oidSnmpTrapOID) && vb.Value.Type == snmpwire.TypeOID {
			notif = vb.Value.OID.String()
		}
		if vb.Name.Equal(oidSnmpTrapEnterprise) && vb.Value.Type == snmpwire.TypeOID {
			enterprise = vb.Value.OID.String()
		}
	}
	if enterprise == "" && p.Enterprise != nil {
		enterprise = p.Enterprise.String()
	}
	return enterprise, notif
}

func convertVarBinds(in []snmpwire.VarBind) []store.VarBind {
	if in == nil {
		return nil
	}
	out := make([]store.VarBind, len(in))
	for i, vb := range in {
		out[i] = store.VarBind{
			OID:      vb.Name.String(),
			Type:     vb.Value.Type.String(),
			Integer:  vb.Value.Int,
			Unsigned: vb.Value.Uint,
			Bytes:    append([]byte(nil), vb.Value.Bytes...),
			OIDValue: vb.Value.OID.String(),
		}
		if vb.Value.Type == snmpwire.TypeIPAddress {
			out[i].Bytes = append([]byte(nil), vb.Value.IP[:]...)
		}
	}
	return out
}
