// Package compiler normalizes, validates, and compiles an immutable snapshot.
// Compile owns map trees, localized USM keys, and uptimeEpoch. It is the
// only compile path after APP-001; snmpagent must not fork a second one.
package compiler
