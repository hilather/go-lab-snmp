package config

import (
	"os"
	"path/filepath"

	"github.com/hilather/go-lab-snmp/internal/model"
)

// Load decodes, normalizes, and validates a YAML or JSON document.
func Load(data []byte) (*model.State, error) {
	st, _, err := LoadWithWarnings(data)
	return st, err
}

// LoadWithWarnings is Load plus non-fatal warnings.
func LoadWithWarnings(data []byte) (*model.State, []Warning, error) {
	return load(data, "")
}

func load(data []byte, baseDir string) (*model.State, []Warning, error) {
	st, err := Decode(data)
	if err != nil {
		return nil, nil, err
	}
	n, warns, err := Normalize(st)
	if err != nil {
		return nil, nil, err
	}
	if err := ValidateWithBaseDir(n, baseDir); err != nil {
		return nil, warns, err
	}
	return n, warns, nil
}

// LoadFile reads path and calls Load, resolving relative secret paths
// against the process working directory then the config file directory.
func LoadFile(path string) (*model.State, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	st, _, err := load(b, filepath.Dir(path))
	return st, err
}

// LoadFileWithWarnings reads path and calls LoadWithWarnings.
func LoadFileWithWarnings(path string) (*model.State, []Warning, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return load(b, filepath.Dir(path))
}
