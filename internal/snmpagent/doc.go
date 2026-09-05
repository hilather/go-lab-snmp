// Package snmpagent is the unicast SNMPv1/v2c/v3 UDP/161 data plane.
//
// Each datagram loads the active snapshot.Store entry. Compile lives in
// compiler; this package must not import internal/app or internal/compiler.
package snmpagent
