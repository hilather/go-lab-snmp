package snmpwire

import (
	"fmt"
)

// Decode parses one SNMP message. b must not exceed DefaultMaxMessageBytes.
func Decode(b []byte) (Message, error) {
	return DecodeMax(b, DefaultMaxMessageBytes)
}

// DecodeMax parses one SNMP message, rejecting input longer than maxBytes.
func DecodeMax(b []byte, maxBytes int64) (Message, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxMessageBytes
	}
	if int64(len(b)) > maxBytes {
		return Message{}, fmt.Errorf("%w (%d > %d)", ErrTooLarge, len(b), maxBytes)
	}
	r := newReader(b)
	content, err := r.sequence()
	if err != nil {
		return Message{}, err
	}
	if r.remaining() != 0 {
		return Message{}, fmt.Errorf("snmpwire: trailing bytes after message: %w", ErrBER)
	}
	mr := newReader(content)
	ver, err := mr.int32()
	if err != nil {
		return Message{}, err
	}
	switch Version(ver) {
	case VersionV1, VersionV2c:
		return decodeCommunity(Version(ver), &mr)
	case VersionV3:
		return decodeV3(&mr)
	default:
		return Message{}, fmt.Errorf("snmpwire: version %d: %w", ver, ErrVersion)
	}
}

func decodeCommunity(ver Version, r *reader) (Message, error) {
	comm, err := r.octetString()
	if err != nil {
		return Message{}, err
	}
	tag, content, err := r.tlv()
	if err != nil {
		return Message{}, err
	}
	if r.remaining() != 0 {
		return Message{}, fmt.Errorf("snmpwire: trailing bytes after PDU: %w", ErrBER)
	}
	p, err := decodePDU(tag, content)
	if err != nil {
		return Message{}, err
	}
	if ver == VersionV1 && p.Type == PDUGetBulk {
		return Message{}, fmt.Errorf("snmpwire: GetBulk is not a v1 PDU: %w", ErrPDU)
	}
	return Message{
		Version:   ver,
		Community: cloneBytes(comm),
		PDU:       p,
	}, nil
}

func decodeV3(r *reader) (Message, error) {
	hdr, err := r.sequence()
	if err != nil {
		return Message{}, err
	}
	hr := newReader(hdr)
	msgID, err := hr.int32()
	if err != nil {
		return Message{}, err
	}
	msgMax, err := hr.int32()
	if err != nil {
		return Message{}, err
	}
	flags, err := hr.octetString()
	if err != nil {
		return Message{}, err
	}
	if len(flags) != 1 {
		return Message{}, fmt.Errorf("snmpwire: msgFlags must be 1 octet: %w", ErrBER)
	}
	model, err := hr.int32()
	if err != nil {
		return Message{}, err
	}
	if hr.remaining() != 0 {
		return Message{}, fmt.Errorf("snmpwire: trailing header bytes: %w", ErrBER)
	}
	sec, err := r.octetString()
	if err != nil {
		return Message{}, err
	}
	m := Message{
		Version:          VersionV3,
		MsgID:            msgID,
		MsgMaxSize:       msgMax,
		MsgFlags:         flags[0],
		MsgSecurityModel: model,
	}
	if model == SecurityModelUSM {
		usm, err := decodeUSM(sec)
		if err != nil {
			return Message{}, err
		}
		m.USM = usm
	}
	tag, content, err := r.tlv()
	if err != nil {
		return Message{}, err
	}
	if r.remaining() != 0 {
		return Message{}, fmt.Errorf("snmpwire: trailing bytes after scopedPDU: %w", ErrBER)
	}
	if m.MsgFlags&FlagPriv != 0 {
		if tag != tagOctetString {
			return Message{}, fmt.Errorf("snmpwire: priv scopedPDU must be OCTET STRING: %w", ErrBER)
		}
		m.EncryptedPDU = cloneBytes(content)
		return m, nil
	}
	if tag != tagSequence {
		return Message{}, fmt.Errorf("snmpwire: plaintext scopedPDU must be SEQUENCE: %w", ErrBER)
	}
	sp, err := decodeScopedPDUContent(content)
	if err != nil {
		return Message{}, err
	}
	m.ScopedPDU = sp
	// Alias so RequestPDU() mutations are visible to Encode.
	m.PDU = &sp.PDU
	return m, nil
}

func decodeUSM(sec []byte) (USMParameters, error) {
	r := newReader(sec)
	body, err := r.sequence()
	if err != nil {
		return USMParameters{}, err
	}
	if r.remaining() != 0 {
		return USMParameters{}, fmt.Errorf("snmpwire: trailing USM parameter bytes: %w", ErrBER)
	}
	ur := newReader(body)
	engineID, err := ur.octetString()
	if err != nil {
		return USMParameters{}, err
	}
	boots, err := ur.int32()
	if err != nil {
		return USMParameters{}, err
	}
	etime, err := ur.int32()
	if err != nil {
		return USMParameters{}, err
	}
	user, err := ur.octetString()
	if err != nil {
		return USMParameters{}, err
	}
	auth, err := ur.octetString()
	if err != nil {
		return USMParameters{}, err
	}
	priv, err := ur.octetString()
	if err != nil {
		return USMParameters{}, err
	}
	if ur.remaining() != 0 {
		return USMParameters{}, fmt.Errorf("snmpwire: trailing USM SEQUENCE bytes: %w", ErrBER)
	}
	return USMParameters{
		EngineID:    cloneBytes(engineID),
		EngineBoots: boots,
		EngineTime:  etime,
		UserName:    cloneBytes(user),
		AuthParams:  cloneBytes(auth),
		PrivParams:  cloneBytes(priv),
	}, nil
}

func decodeScopedPDUContent(content []byte) (*ScopedPDU, error) {
	r := newReader(content)
	ce, err := r.octetString()
	if err != nil {
		return nil, err
	}
	cn, err := r.octetString()
	if err != nil {
		return nil, err
	}
	tag, pduContent, err := r.tlv()
	if err != nil {
		return nil, err
	}
	if r.remaining() != 0 {
		return nil, fmt.Errorf("snmpwire: trailing scopedPDU bytes: %w", ErrBER)
	}
	p, err := decodePDU(tag, pduContent)
	if err != nil {
		return nil, err
	}
	return &ScopedPDU{
		ContextEngineID: cloneBytes(ce),
		ContextName:     cloneBytes(cn),
		PDU:             *p,
	}, nil
}

// DecodeScopedPDU parses a plaintext scopedPDU SEQUENCE (after USM decrypt).
func DecodeScopedPDU(b []byte) (ScopedPDU, error) {
	r := newReader(b)
	content, err := r.sequence()
	if err != nil {
		return ScopedPDU{}, err
	}
	if r.remaining() != 0 {
		return ScopedPDU{}, fmt.Errorf("snmpwire: trailing bytes after scopedPDU: %w", ErrBER)
	}
	sp, err := decodeScopedPDUContent(content)
	if err != nil {
		return ScopedPDU{}, err
	}
	return *sp, nil
}

// EncodeScopedPDU encodes a plaintext scopedPDU (before USM encrypt).
func EncodeScopedPDU(s ScopedPDU) ([]byte, error) {
	body, err := encodeScopedPDUContent(s)
	if err != nil {
		return nil, err
	}
	return encodeSequence(body), nil
}

func encodeScopedPDUContent(s ScopedPDU) ([]byte, error) {
	pdu, err := encodePDU(&s.PDU)
	if err != nil {
		return nil, err
	}
	var body []byte
	body = append(body, encodeOctetString(s.ContextEngineID)...)
	body = append(body, encodeOctetString(s.ContextName)...)
	body = append(body, pdu...)
	return body, nil
}

func encodeUSM(u USMParameters) []byte {
	var body []byte
	body = append(body, encodeOctetString(u.EngineID)...)
	body = append(body, encodeInteger(int64(u.EngineBoots))...)
	body = append(body, encodeInteger(int64(u.EngineTime))...)
	body = append(body, encodeOctetString(u.UserName)...)
	body = append(body, encodeOctetString(u.AuthParams)...)
	body = append(body, encodeOctetString(u.PrivParams)...)
	return encodeOctetString(encodeSequence(body))
}

// Encode serializes m. The result must not exceed DefaultMaxMessageBytes.
func Encode(m Message) ([]byte, error) {
	return EncodeMax(m, DefaultMaxMessageBytes)
}

// EncodeMax serializes m, rejecting results larger than maxBytes.
func EncodeMax(m Message, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxMessageBytes
	}
	var body []byte
	switch m.Version {
	case VersionV1, VersionV2c:
		b, err := encodeCommunity(m)
		if err != nil {
			return nil, err
		}
		body = b
	case VersionV3:
		b, err := encodeV3(m)
		if err != nil {
			return nil, err
		}
		body = b
	default:
		return nil, fmt.Errorf("snmpwire: version %d: %w", int32(m.Version), ErrVersion)
	}
	out := encodeSequence(body)
	if int64(len(out)) > maxBytes {
		return nil, fmt.Errorf("%w (%d > %d)", ErrTooLarge, len(out), maxBytes)
	}
	return out, nil
}

func encodeCommunity(m Message) ([]byte, error) {
	if m.Version == VersionV1 && m.PDU != nil && m.PDU.Type == PDUGetBulk {
		return nil, fmt.Errorf("snmpwire: GetBulk is not a v1 PDU: %w", ErrPDU)
	}
	pdu, err := encodePDU(m.PDU)
	if err != nil {
		return nil, err
	}
	var body []byte
	body = append(body, encodeInteger(int64(m.Version))...)
	body = append(body, encodeOctetString(m.Community)...)
	body = append(body, pdu...)
	return body, nil
}

func encodeV3(m Message) ([]byte, error) {
	var flags [1]byte
	flags[0] = m.MsgFlags
	var hdr []byte
	hdr = append(hdr, encodeInteger(int64(m.MsgID))...)
	hdr = append(hdr, encodeInteger(int64(m.MsgMaxSize))...)
	hdr = append(hdr, encodeOctetString(flags[:])...)
	hdr = append(hdr, encodeInteger(int64(m.MsgSecurityModel))...)

	var body []byte
	body = append(body, encodeInteger(int64(VersionV3))...)
	body = append(body, encodeSequence(hdr)...)
	body = append(body, encodeUSM(m.USM)...)

	if m.MsgFlags&FlagPriv != 0 {
		body = append(body, encodeOctetString(m.EncryptedPDU)...)
		return body, nil
	}
	var scoped ScopedPDU
	switch {
	case m.ScopedPDU != nil:
		scoped = *m.ScopedPDU
		if m.PDU != nil {
			scoped.PDU = *m.PDU
		}
	case m.PDU != nil:
		scoped.PDU = *m.PDU
	default:
		return nil, fmt.Errorf("snmpwire: v3 plaintext requires ScopedPDU: %w", ErrPDU)
	}
	content, err := encodeScopedPDUContent(scoped)
	if err != nil {
		return nil, err
	}
	body = append(body, encodeSequence(content)...)
	return body, nil
}
