// Package observability is slog JSON logs and hand-rolled OpenMetrics.
// There is no Prometheus client dependency.
package observability

import "errors"

// CatalogRelPath is the generated metrics catalog, relative to the module root.
const CatalogRelPath = "api/metrics/v1alpha1.json"

// RenderCatalog is implemented by OBS-001. Until then generate fails closed.
func RenderCatalog() ([]byte, error) {
	return nil, errors.New("metrics catalog is not generated until OBS-001")
}
