// Package snmpagent is the unicast SNMPv1/v2c/v3 agent data plane
// (UDP, RFC 3430 TCP, and DTLS 1.2 record layer).
//
// Each request loads the active snapshot.Store entry. Compile lives in
// compiler; this package must not import internal/app or internal/compiler.
package snmpagent
