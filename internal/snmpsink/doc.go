// Package snmpsink is the receive-only UDP/162 trap and inform sink.
//
// INFORM acknowledgements are WriteTo on the trap socket. This package
// must not Dial.
package snmpsink
