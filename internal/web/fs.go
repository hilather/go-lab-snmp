package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// UIEnabled gates serving the embedded SPA. The management server
// serves the embed only when this is true.
const UIEnabled = false

// Files returns the committed dist tree. go:embed cannot target an empty directory.
func Files() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return dist
	}
	return sub
}
