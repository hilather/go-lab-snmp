// Package snmpsink is the receive-only trap and inform sink (UDP/162,
// RFC 3430 TCP, and DTLS 1.2 record layer).
//
// INFORM and v3 Report share one ack path: WriteTo on UDP, WriteTCP on
// TCP, Write on the accepted DTLS connection. This package must not Dial.
// When Config.Snapshots is set, each PDU loads communities, USM users,
// admission, and trap-policy flags from it.
package snmpsink
