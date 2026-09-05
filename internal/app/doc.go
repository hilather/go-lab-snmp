// Package app is the HTTP-less capability surface. REST and MCP call these
// methods rather than implementing mutation or query logic.
//
// Data-plane packages must not import app. cmd/labsnmp may import app
// for plan/apply/reset. SET overlay is not an apply verb.
package app
