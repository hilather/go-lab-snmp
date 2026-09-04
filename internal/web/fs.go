package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// UIEnabled is false until UI-001 replaces dist with a real Vite tree.
const UIEnabled = false

// Files returns the committed dist tree. go:embed cannot target an empty directory.
func Files() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return dist
	}
	return sub
}
