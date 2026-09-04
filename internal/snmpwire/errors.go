package snmpwire

import "errors"

var (
	ErrTooLarge  = errors.New("snmpwire: message exceeds max size")
	ErrTruncated = errors.New("snmpwire: truncated BER")
	ErrBER       = errors.New("snmpwire: invalid BER")
	ErrVersion   = errors.New("snmpwire: unsupported SNMP version")
	ErrPDU       = errors.New("snmpwire: invalid PDU")
	ErrValue     = errors.New("snmpwire: invalid value")
	ErrOID       = errors.New("snmpwire: invalid OBJECT IDENTIFIER")
)
