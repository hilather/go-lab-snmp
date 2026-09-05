package snmpagent

import (
	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
)

func toMIBOID(oid snmpwire.OID) mibtree.OID {
	if oid == nil {
		return nil
	}
	out := make(mibtree.OID, len(oid))
	copy(out, oid)
	return out
}

func toWireOID(oid mibtree.OID) snmpwire.OID {
	if oid == nil {
		return nil
	}
	out := make(snmpwire.OID, len(oid))
	copy(out, oid)
	return out
}

func fromWireValue(v snmpwire.Value) mibtree.Value {
	switch v.Type {
	case snmpwire.TypeInteger:
		return mibtree.Value{Type: model.TypeInteger, Signed: v.Int}
	case snmpwire.TypeOctetString:
		return mibtree.Value{Type: model.TypeOctetString, Bytes: append([]byte(nil), v.Bytes...)}
	case snmpwire.TypeNull:
		return mibtree.Value{Type: model.TypeNull}
	case snmpwire.TypeOID:
		return mibtree.Value{Type: model.TypeObjectIdentifier, OID: toMIBOID(v.OID)}
	case snmpwire.TypeIPAddress:
		b := make([]byte, 4)
		copy(b, v.IP[:])
		return mibtree.Value{Type: model.TypeIPAddress, Bytes: b}
	case snmpwire.TypeCounter32:
		return mibtree.Value{Type: model.TypeCounter32, Unsigned: v.Uint}
	case snmpwire.TypeGauge32:
		return mibtree.Value{Type: model.TypeGauge32, Unsigned: v.Uint}
	case snmpwire.TypeUnsigned32:
		return mibtree.Value{Type: model.TypeUnsigned32, Unsigned: v.Uint}
	case snmpwire.TypeTimeTicks:
		return mibtree.Value{Type: model.TypeTimeTicks, Unsigned: v.Uint}
	case snmpwire.TypeOpaque:
		return mibtree.Value{Type: model.TypeOpaque, Bytes: append([]byte(nil), v.Bytes...)}
	case snmpwire.TypeCounter64:
		return mibtree.Value{Type: model.TypeCounter64, Unsigned: v.Uint}
	default:
		return mibtree.Value{}
	}
}

func toWireValue(v mibtree.Value) snmpwire.Value {
	switch v.Type {
	case model.TypeInteger:
		return snmpwire.Int(v.Signed)
	case model.TypeOctetString:
		return snmpwire.OctetString(v.Bytes)
	case model.TypeNull:
		return snmpwire.Null()
	case model.TypeObjectIdentifier:
		return snmpwire.ObjectIdentifier(toWireOID(v.OID))
	case model.TypeIPAddress:
		var ip [4]byte
		copy(ip[:], v.Bytes)
		return snmpwire.IPAddr(ip)
	case model.TypeCounter32:
		return snmpwire.Counter32Val(uint32(v.Unsigned))
	case model.TypeGauge32:
		return snmpwire.Gauge32Val(uint32(v.Unsigned))
	case model.TypeUnsigned32:
		return snmpwire.Unsigned32Val(uint32(v.Unsigned))
	case model.TypeTimeTicks:
		return snmpwire.TimeTicksVal(uint32(v.Unsigned))
	case model.TypeOpaque:
		return snmpwire.OpaqueVal(v.Bytes)
	case model.TypeCounter64:
		return snmpwire.Counter64Val(v.Unsigned)
	default:
		return snmpwire.Null()
	}
}

func exceptionValue(ex mibtree.Exception) snmpwire.Value {
	switch ex {
	case mibtree.NoSuchObject:
		return snmpwire.NoSuchObjectVal()
	case mibtree.NoSuchInstance:
		return snmpwire.NoSuchInstanceVal()
	case mibtree.EndOfMibView:
		return snmpwire.EndOfMibViewVal()
	default:
		return snmpwire.Null()
	}
}

func resultBind(res mibtree.Result) snmpwire.VarBind {
	if res.Exception != mibtree.NoException {
		return snmpwire.VarBind{Name: toWireOID(res.OID), Value: exceptionValue(res.Exception)}
	}
	return snmpwire.VarBind{Name: toWireOID(res.OID), Value: toWireValue(res.Value)}
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
		return ""
	}
}
