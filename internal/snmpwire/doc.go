// Package snmpwire is the first-party SNMPv1/v2c/v3 BER codec.
//
// It does not import an SNMP library. SNMPv3 privacy is represented as an
// OCTET STRING ciphertext; HMAC and decrypt belong to internal/usm.
package snmpwire
