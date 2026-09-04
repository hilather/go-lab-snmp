package snmpwire

import (
	"fmt"
)

func encodeValue(v Value) ([]byte, error) {
	switch v.Type {
	case TypeInteger:
		if v.Int < -1<<31 || v.Int > 1<<31-1 {
			return nil, fmt.Errorf("snmpwire: INTEGER out of Integer32 range: %w", ErrValue)
		}
		return encodeInteger(v.Int), nil
	case TypeOctetString:
		return encodeOctetString(v.Bytes), nil
	case TypeNull:
		return encodeNull(), nil
	case TypeOID:
		return encodeOID(v.OID)
	case TypeIPAddress:
		return wrap(tagIPAddress, v.IP[:]), nil
	case TypeCounter32:
		if v.Uint > 1<<32-1 {
			return nil, fmt.Errorf("snmpwire: Counter32 overflow: %w", ErrValue)
		}
		return wrap(tagCounter32, encodeUint(v.Uint)), nil
	case TypeGauge32, TypeUnsigned32:
		if v.Uint > 1<<32-1 {
			return nil, fmt.Errorf("snmpwire: Gauge32 overflow: %w", ErrValue)
		}
		return wrap(tagGauge32, encodeUint(v.Uint)), nil
	case TypeTimeTicks:
		if v.Uint > 1<<32-1 {
			return nil, fmt.Errorf("snmpwire: TimeTicks overflow: %w", ErrValue)
		}
		return wrap(tagTimeTicks, encodeUint(v.Uint)), nil
	case TypeOpaque:
		return wrap(tagOpaque, v.Bytes), nil
	case TypeCounter64:
		return wrap(tagCounter64, encodeUint(v.Uint)), nil
	case TypeNoSuchObject:
		return []byte{tagNoSuchObject, 0}, nil
	case TypeNoSuchInstance:
		return []byte{tagNoSuchInstance, 0}, nil
	case TypeEndOfMibView:
		return []byte{tagEndOfMibView, 0}, nil
	default:
		return nil, fmt.Errorf("snmpwire: unknown value type %d: %w", int(v.Type), ErrValue)
	}
}

func decodeValue(tag byte, content []byte) (Value, error) {
	switch tag {
	case tagInteger:
		n, err := decodeSigned(content)
		if err != nil {
			return Value{}, err
		}
		if n < -1<<31 || n > 1<<31-1 {
			return Value{}, fmt.Errorf("snmpwire: INTEGER out of Integer32 range: %w", ErrValue)
		}
		return Int(n), nil
	case tagOctetString:
		return OctetString(content), nil
	case tagNull:
		if len(content) != 0 {
			return Value{}, fmt.Errorf("snmpwire: NULL with contents: %w", ErrValue)
		}
		return Null(), nil
	case tagOID:
		oid, err := decodeOID(content)
		if err != nil {
			return Value{}, err
		}
		return ObjectIdentifier(oid), nil
	case tagIPAddress:
		if len(content) != 4 {
			return Value{}, fmt.Errorf("snmpwire: IpAddress must be 4 octets: %w", ErrValue)
		}
		var ip [4]byte
		copy(ip[:], content)
		return IPAddr(ip), nil
	case tagCounter32:
		n, err := decodeUnsigned32(content)
		if err != nil {
			return Value{}, err
		}
		return Counter32Val(n), nil
	case tagGauge32:
		n, err := decodeUnsigned32(content)
		if err != nil {
			return Value{}, err
		}
		return Gauge32Val(n), nil
	case tagTimeTicks:
		n, err := decodeUnsigned32(content)
		if err != nil {
			return Value{}, err
		}
		return TimeTicksVal(n), nil
	case tagOpaque:
		return OpaqueVal(content), nil
	case tagCounter64:
		n, err := decodeUnsigned(content)
		if err != nil {
			return Value{}, err
		}
		return Counter64Val(n), nil
	case tagNoSuchObject:
		if len(content) != 0 {
			return Value{}, fmt.Errorf("snmpwire: noSuchObject with contents: %w", ErrValue)
		}
		return NoSuchObjectVal(), nil
	case tagNoSuchInstance:
		if len(content) != 0 {
			return Value{}, fmt.Errorf("snmpwire: noSuchInstance with contents: %w", ErrValue)
		}
		return NoSuchInstanceVal(), nil
	case tagEndOfMibView:
		if len(content) != 0 {
			return Value{}, fmt.Errorf("snmpwire: endOfMibView with contents: %w", ErrValue)
		}
		return EndOfMibViewVal(), nil
	default:
		return Value{}, fmt.Errorf("snmpwire: unknown varbind tag 0x%02x: %w", tag, ErrValue)
	}
}

func decodeUnsigned32(content []byte) (uint32, error) {
	n, err := decodeUnsigned(content)
	if err != nil {
		return 0, err
	}
	if n > 1<<32-1 {
		return 0, fmt.Errorf("snmpwire: unsigned 32-bit overflow: %w", ErrValue)
	}
	return uint32(n), nil
}
