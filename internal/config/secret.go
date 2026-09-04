package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

func readSecretFile(path, baseDir string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, os.ErrNotExist
	}
	candidates := []string{path}
	if !filepath.IsAbs(path) {
		if baseDir != "" {
			rel := filepath.Join(baseDir, path)
			if rel != path {
				candidates = append(candidates, rel)
			}
			if root, err := findModuleRootFrom(baseDir); err == nil {
				rel := filepath.Join(root, path)
				if rel != path {
					candidates = append(candidates, rel)
				}
			}
		}
		if root, err := findModuleRoot(); err == nil {
			rel := filepath.Join(root, path)
			if rel != path {
				candidates = append(candidates, rel)
			}
		}
	}
	var firstErr error
	for _, c := range candidates {
		b, err := os.ReadFile(c)
		if err == nil {
			return b, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

func trimmedSecret(path, baseDir string) ([]byte, error) {
	b, err := readSecretFile(path, baseDir)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(b), nil
}
