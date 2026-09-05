// Package mcp is the official SDK Streamable HTTP adapter. It calls app.Service
// only and must not import internal/control/rest.
package mcp

import "errors"

// ManifestRelPath is the generated MCP catalog, relative to the module root.
const ManifestRelPath = "api/mcp/v1.json"

// RenderManifest is implemented by MCP-001. Until then generate fails closed.
func RenderManifest() ([]byte, error) {
	return nil, errors.New("mcp catalog is not generated until MCP-001")
}
