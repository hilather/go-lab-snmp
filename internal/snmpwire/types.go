package snmpwire

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// DefaultMaxMessageBytes is spec.agent.maxMessageBytes default (64KiB).
const DefaultMaxMessageBytes = int64(64 << 10)

const (
	maxBERLengthBytes = 4
	maxOIDArcs        = 128
)

// Version is the SNMP message version INTEGER (RFC 3416 / 3412).
type Version int32

const (
	VersionV1  Version = 0
	VersionV2c Version = 1
	VersionV3  Version = 3
)

func (v Version) String() string {
	switch v {
	case VersionV1:
		return "v1"
	case VersionV2c:
		return "v2c"
	case VersionV3:
		return "v3"
	default:
		return fmt.Sprintf("version(%d)", int32(v))
	}
}

// PDUType is the context-specific PDU tag number (RFC 3416).
type PDUType int

const (
	PDUGet      PDUType = 0
	PDUGetNext  PDUType = 1
	PDUResponse PDUType = 2
	PDUSet      PDUType = 3
	PDUTrapV1   PDUType = 4
	PDUGetBulk  PDUType = 5
	PDUInform   PDUType = 6
	PDUTrapV2   PDUType = 7
	PDUReport   PDUType = 8
)

func (t PDUType) String() string {
	switch t {
	case PDUGet:
		return "get"
	case PDUGetNext:
		return "getnext"
	case PDUResponse:
		return "response"
	case PDUSet:
		return "set"
	case PDUTrapV1:
		return "trapv1"
	case PDUGetBulk:
		return "getbulk"
	case PDUInform:
		return "inform"
	case PDUTrapV2:
		return "trapv2"
	case PDUReport:
		return "report"
	default:
		return fmt.Sprintf("pdu(%d)", int(t))
	}
}

// SNMPv3 msgFlags bits (RFC 3412).
const (
	FlagAuth       byte = 0x01
	FlagPriv       byte = 0x02
	FlagReportable byte = 0x04
)

// SecurityModelUSM is RFC 3411 snmpSecurityModels usm (3).
const SecurityModelUSM int32 = 3

// RFC 3416 error-status values.
const (
	ErrorStatusNoError             int32 = 0
	ErrorStatusTooBig              int32 = 1
	ErrorStatusNoSuchName          int32 = 2
	ErrorStatusBadValue            int32 = 3
	ErrorStatusReadOnly            int32 = 4
	ErrorStatusGenErr              int32 = 5
	ErrorStatusNoAccess            int32 = 6
	ErrorStatusWrongType           int32 = 7
	ErrorStatusWrongLength         int32 = 8
	ErrorStatusWrongEncoding       int32 = 9
	ErrorStatusWrongValue          int32 = 10
	ErrorStatusNoCreation          int32 = 11
	ErrorStatusInconsistentValue   int32 = 12
	ErrorStatusResourceUnavailable int32 = 13
	ErrorStatusCommitFailed        int32 = 14
	ErrorStatusUndoFailed          int32 = 15
	ErrorStatusAuthorizationError  int32 = 16
	ErrorStatusNotWritable         int32 = 17
	ErrorStatusInconsistentName    int32 = 18
)

// RFC 1157 generic-trap values.
const (
	TrapColdStart             int32 = 0
	TrapWarmStart             int32 = 1
	TrapLinkDown              int32 = 2
	TrapLinkUp                int32 = 3
	TrapAuthenticationFailure int32 = 4
	TrapEGPNeighborLoss       int32 = 5
	TrapEnterpriseSpecific    int32 = 6
)

// Type is a varbind syntax (RFC 3416) plus v2 exception tags.
type Type int

const (
	TypeInteger Type = iota
	TypeOctetString
	TypeNull
	TypeOID
	TypeIPAddress
	TypeCounter32
	TypeGauge32
	TypeUnsigned32 // same application tag as Gauge32
	TypeTimeTicks
	TypeOpaque
	TypeCounter64
	TypeNoSuchObject
	TypeNoSuchInstance
	TypeEndOfMibView
)

func (t Type) String() string {
	switch t {
	case TypeInteger:
		return "integer"
	case TypeOctetString:
		return "octetString"
	case TypeNull:
		return "null"
	case TypeOID:
		return "objectIdentifier"
	case TypeIPAddress:
		return "ipAddress"
	case TypeCounter32:
		return "counter32"
	case TypeGauge32:
		return "gauge32"
	case TypeUnsigned32:
		return "unsigned32"
	case TypeTimeTicks:
		return "timeTicks"
	case TypeOpaque:
		return "opaque"
	case TypeCounter64:
		return "counter64"
	case TypeNoSuchObject:
		return "noSuchObject"
	case TypeNoSuchInstance:
		return "noSuchInstance"
	case TypeEndOfMibView:
		return "endOfMibView"
	default:
		return fmt.Sprintf("type(%d)", int(t))
	}
}

// OID is a dotted OBJECT IDENTIFIER as unsigned arcs.
type OID []uint32

func (o OID) String() string {
	if len(o) == 0 {
		return ""
	}
	var b strings.Builder
	for i, a := range o {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(uint64(a), 10))
	}
	return b.String()
}

// Equal reports whether o and p have the same arcs.
func (o OID) Equal(p OID) bool {
	if len(o) != len(p) {
		return false
	}
	for i := range o {
		if o[i] != p[i] {
			return false
		}
	}
	return true
}

func (o OID) clone() OID {
	if o == nil {
		return nil
	}
	out := make(OID, len(o))
	copy(out, o)
	return out
}

// Value is one varbind syntax value. Bytes and OID are owned by Value.
type Value struct {
	Type  Type
	Int   int64
	Uint  uint64
	Bytes []byte
	OID   OID
	IP    [4]byte
}

// Null is the BER NULL value.
func Null() Value { return Value{Type: TypeNull} }

// Int returns an INTEGER / Integer32 value.
func Int(v int64) Value { return Value{Type: TypeInteger, Int: v} }

// OctetString returns an OCTET STRING value.
func OctetString(b []byte) Value {
	return Value{Type: TypeOctetString, Bytes: bytes.Clone(b)}
}

// ObjectIdentifier returns an OBJECT IDENTIFIER value.
func ObjectIdentifier(oid OID) Value {
	return Value{Type: TypeOID, OID: oid.clone()}
}

// IPAddr returns an IpAddress value.
func IPAddr(ip [4]byte) Value { return Value{Type: TypeIPAddress, IP: ip} }

// Counter32Val returns a Counter32 value.
func Counter32Val(v uint32) Value { return Value{Type: TypeCounter32, Uint: uint64(v)} }

// Gauge32Val returns a Gauge32 value.
func Gauge32Val(v uint32) Value { return Value{Type: TypeGauge32, Uint: uint64(v)} }

// Unsigned32Val returns an Unsigned32 value (Gauge32 tag).
func Unsigned32Val(v uint32) Value { return Value{Type: TypeUnsigned32, Uint: uint64(v)} }

// TimeTicksVal returns a TimeTicks value.
func TimeTicksVal(v uint32) Value { return Value{Type: TypeTimeTicks, Uint: uint64(v)} }

// OpaqueVal returns an Opaque value.
func OpaqueVal(b []byte) Value {
	return Value{Type: TypeOpaque, Bytes: bytes.Clone(b)}
}

// Counter64Val returns a Counter64 value.
func Counter64Val(v uint64) Value { return Value{Type: TypeCounter64, Uint: v} }

// NoSuchObjectVal is the SNMPv2 exception.
func NoSuchObjectVal() Value { return Value{Type: TypeNoSuchObject} }

// NoSuchInstanceVal is the SNMPv2 exception.
func NoSuchInstanceVal() Value { return Value{Type: TypeNoSuchInstance} }

// EndOfMibViewVal is the SNMPv2 exception.
func EndOfMibViewVal() Value { return Value{Type: TypeEndOfMibView} }

// Equal reports semantic equality, treating nil and empty slices as equal.
func (v Value) Equal(o Value) bool {
	if v.Type != o.Type || v.Int != o.Int || v.Uint != o.Uint || v.IP != o.IP {
		return false
	}
	if !bytes.Equal(v.Bytes, o.Bytes) {
		return false
	}
	return v.OID.Equal(o.OID)
}

func (v Value) clone() Value {
	out := v
	out.Bytes = bytes.Clone(v.Bytes)
	out.OID = v.OID.clone()
	return out
}

// VarBind is one name/value pair.
type VarBind struct {
	Name  OID
	Value Value
}

func (v VarBind) clone() VarBind {
	return VarBind{Name: v.Name.clone(), Value: v.Value.clone()}
}

// Equal reports semantic equality.
func (v VarBind) Equal(o VarBind) bool {
	return v.Name.Equal(o.Name) && v.Value.Equal(o.Value)
}

// PDU is a decoded SNMP PDU. GetBulk uses NonRepeaters/MaxRepetitions
// in place of ErrorStatus/ErrorIndex. Trap-v1 uses the enterprise fields.
type PDU struct {
	Type PDUType

	RequestID   int32
	ErrorStatus int32
	ErrorIndex  int32

	NonRepeaters   int32
	MaxRepetitions int32

	Enterprise   OID
	AgentAddr    [4]byte
	GenericTrap  int32
	SpecificTrap int32
	Timestamp    uint32

	VarBinds []VarBind
}

func (p *PDU) clone() *PDU {
	if p == nil {
		return nil
	}
	out := *p
	out.Enterprise = p.Enterprise.clone()
	if p.VarBinds != nil {
		out.VarBinds = make([]VarBind, len(p.VarBinds))
		for i := range p.VarBinds {
			out.VarBinds[i] = p.VarBinds[i].clone()
		}
	}
	return &out
}

// Equal reports semantic equality.
func (p *PDU) Equal(o *PDU) bool {
	if p == nil || o == nil {
		return p == o
	}
	if p.Type != o.Type || p.RequestID != o.RequestID ||
		p.ErrorStatus != o.ErrorStatus || p.ErrorIndex != o.ErrorIndex ||
		p.NonRepeaters != o.NonRepeaters || p.MaxRepetitions != o.MaxRepetitions ||
		p.AgentAddr != o.AgentAddr || p.GenericTrap != o.GenericTrap ||
		p.SpecificTrap != o.SpecificTrap || p.Timestamp != o.Timestamp {
		return false
	}
	if !p.Enterprise.Equal(o.Enterprise) {
		return false
	}
	if len(p.VarBinds) != len(o.VarBinds) {
		return false
	}
	for i := range p.VarBinds {
		if !p.VarBinds[i].Equal(o.VarBinds[i]) {
			return false
		}
	}
	return true
}

// USMParameters is RFC 3414 UsmSecurityParameters. AuthParams and
// PrivParams are opaque; this package does not HMAC or decrypt.
type USMParameters struct {
	EngineID    []byte
	EngineBoots int32
	EngineTime  int32
	UserName    []byte
	AuthParams  []byte
	PrivParams  []byte
}

// Equal reports semantic equality.
func (u USMParameters) Equal(o USMParameters) bool {
	return bytes.Equal(u.EngineID, o.EngineID) &&
		u.EngineBoots == o.EngineBoots &&
		u.EngineTime == o.EngineTime &&
		bytes.Equal(u.UserName, o.UserName) &&
		bytes.Equal(u.AuthParams, o.AuthParams) &&
		bytes.Equal(u.PrivParams, o.PrivParams)
}

// ScopedPDU is RFC 3412 plaintext scopedPDU.
type ScopedPDU struct {
	ContextEngineID []byte
	ContextName     []byte
	PDU             PDU
}

// Equal reports semantic equality.
func (s *ScopedPDU) Equal(o *ScopedPDU) bool {
	if s == nil || o == nil {
		return s == o
	}
	return bytes.Equal(s.ContextEngineID, o.ContextEngineID) &&
		bytes.Equal(s.ContextName, o.ContextName) &&
		s.PDU.Equal(&o.PDU)
}

// Message is a decoded SNMPv1/v2c/v3 message. No third-party SNMP types.
type Message struct {
	Version   Version
	Community []byte
	PDU       *PDU

	MsgID            int32
	MsgMaxSize       int32
	MsgFlags         byte
	MsgSecurityModel int32
	USM              USMParameters
	ScopedPDU        *ScopedPDU
	// EncryptedPDU is scopedPDU ciphertext when FlagPriv is set.
	EncryptedPDU []byte
}

// Auth reports the msgFlags auth bit.
func (m Message) Auth() bool { return m.MsgFlags&FlagAuth != 0 }

// Priv reports the msgFlags priv bit.
func (m Message) Priv() bool { return m.MsgFlags&FlagPriv != 0 }

// Reportable reports the msgFlags reportable bit.
func (m Message) Reportable() bool { return m.MsgFlags&FlagReportable != 0 }

// RequestPDU returns the decoded PDU, or nil when only ciphertext is present.
func (m Message) RequestPDU() *PDU {
	if m.PDU != nil {
		return m.PDU
	}
	if m.ScopedPDU != nil {
		return &m.ScopedPDU.PDU
	}
	return nil
}

// Equal reports semantic equality.
func (m Message) Equal(o Message) bool {
	if m.Version != o.Version ||
		!bytes.Equal(m.Community, o.Community) ||
		m.MsgID != o.MsgID ||
		m.MsgMaxSize != o.MsgMaxSize ||
		m.MsgFlags != o.MsgFlags ||
		m.MsgSecurityModel != o.MsgSecurityModel ||
		!bytes.Equal(m.EncryptedPDU, o.EncryptedPDU) {
		return false
	}
	if !m.USM.Equal(o.USM) {
		return false
	}
	if !m.PDU.Equal(o.PDU) {
		return false
	}
	return m.ScopedPDU.Equal(o.ScopedPDU)
}
