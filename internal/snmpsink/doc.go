// Package snmpsink is the receive-only UDP/162 trap and inform sink.
//
// INFORM acknowledgements are WriteTo on the trap socket. This package
// must not Dial. When Config.Snapshots is set, each datagram loads
// communities, USM users, admission, and trap-policy flags from it.
package snmpsink
