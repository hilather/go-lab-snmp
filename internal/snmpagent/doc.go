// Package snmpagent is the unicast SNMPv1/v2c/v3 UDP/161 data plane.
//
// Load hand-wires config + mibtree.Compile + USM localization into Runtime
// until APP-001 replaces that path with compiler.Compile. This package
// must not import internal/app, internal/compiler, or internal/snapshot.
package snmpagent
