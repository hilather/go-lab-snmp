package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

func readSecretFile(path, baseDir string) ([]byte, error) {
	resolved, err := ResolveFileRef(path, baseDir)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(resolved)
}

// ResolveFileRef tries path in the working directory, then joined with baseDir.
func ResolveFileRef(path, baseDir string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", os.ErrNotExist
	}
	if filepath.IsAbs(path) {
		if err := regularFile(path); err != nil {
			return "", err
		}
		return path, nil
	}
	candidates := []string{path}
	if baseDir != "" {
		rel := filepath.Join(baseDir, path)
		if rel != path {
			candidates = append(candidates, rel)
		}
	}
	var firstErr error
	for _, c := range candidates {
		if err := regularFile(c); err == nil {
			return c, nil
		} else if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = os.ErrNotExist
	}
	return "", firstErr
}

func regularFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return os.ErrNotExist
	}
	return nil
}

func trimmedSecret(path, baseDir string) ([]byte, error) {
	b, err := readSecretFile(path, baseDir)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(b), nil
}
