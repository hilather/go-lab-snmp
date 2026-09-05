package observability

import (
	"encoding/json"
	"sort"
)

// CatalogID is the versioned metrics/events document identifier.
const CatalogID = "labsnmp.dev/metrics/v1alpha1"

// CatalogRelPath is the generated catalog artifact.
const CatalogRelPath = "api/metrics/v1alpha1.json"

// Kind is a catalog metric type.
type Kind string

const (
	KindCounter   Kind = "counter"
	KindGauge     Kind = "gauge"
	KindHistogram Kind = "histogram"
)

// Frozen metric names. Do not rename.
const (
	MetricPDUsTotal         = "labsnmp_pdus_total"
	MetricTrapsTotal        = "labsnmp_traps_total"
	MetricStoreMessages     = "labsnmp_store_messages"
	MetricStoreBytes        = "labsnmp_store_bytes"
	MetricApplyTotal        = "labsnmp_apply_total"
	MetricHTTPRequestsTotal = "labsnmp_http_requests_total"
	MetricBuildInfo         = "labsnmp_build_info"
	MetricAuthFailTotal     = "labsnmp_auth_fail_total"
	MetricTelemetryDropped  = "labsnmp_telemetry_dropped_total"
	MetricListenersBound    = "labsnmp_listeners_bound"
)

// Frozen structured-log event names.
const (
	EventSNMPPDU     = "snmp.pdu"
	EventSNMPTrap    = "snmp.trap"
	EventStateApply  = "state.apply"
	EventStateReset  = "state.reset"
	EventAuthFailure = "auth.failure"
	EventHTTPRequest = "http.request"
)

// AllowedLabels is the default bounded label set. Client IPs and secrets are never allowed.
var AllowedLabels = []string{
	"capability",
	"code",
	"commit",
	"component",
	"decision",
	"event",
	"pdu",
	"reason",
	"result",
	"route",
	"version",
}

// ForbiddenLabels must never appear on a catalog metric or recorded sample.
var ForbiddenLabels = []string{
	"actor",
	"actor_id",
	"address",
	"authorization",
	"body",
	"client",
	"client_ip",
	"community",
	"community_string",
	"cookie",
	"data",
	"detail",
	"err",
	"error",
	"error_text",
	"from",
	"host",
	"idempotency",
	"idempotency_key",
	"message",
	"passphrase",
	"password",
	"peer",
	"raw",
	"remote_addr",
	"secret",
	"set_cookie",
	"source_ip",
	"src",
	"src_ip",
	"subject",
	"to",
	"token",
}

// MetricDef is one catalog row.
type MetricDef struct {
	Name   string   `json:"name"`
	Kind   Kind     `json:"kind"`
	Help   string   `json:"help"`
	Labels []string `json:"labels"`
	Unit   string   `json:"unit,omitempty"`
}

// EventDef is one stable structured-log event.
type EventDef struct {
	Name   string   `json:"name"`
	Fields []string `json:"fields"`
}

// Document is the versioned catalog artifact.
type Document struct {
	ID              string      `json:"id"`
	Version         string      `json:"version"`
	AllowedLabels   []string    `json:"allowedLabels"`
	ForbiddenLabels []string    `json:"forbiddenLabels"`
	Metrics         []MetricDef `json:"metrics"`
	Events          []EventDef  `json:"events"`
}

// EventFields is the frozen slog JSON field set.
var EventFields = []string{
	"timestamp", "level", "event", "component", "request_id",
	"capability", "result", "error_code", "duration_ms",
}

// Metrics returns the frozen first-GA catalog in stable name order.
func Metrics() []MetricDef {
	defs := []MetricDef{
		{Name: MetricPDUsTotal, Kind: KindCounter, Help: "SNMP PDUs by version, PDU type, and decision.", Labels: []string{"version", "pdu", "decision"}},
		{Name: MetricTrapsTotal, Kind: KindCounter, Help: "Trap and inform datagrams by version and decision.", Labels: []string{"version", "decision"}},
		{Name: MetricStoreMessages, Kind: KindGauge, Help: "Trap inbox message count.", Labels: nil},
		{Name: MetricStoreBytes, Kind: KindGauge, Help: "Trap inbox retained bytes.", Labels: nil},
		{Name: MetricApplyTotal, Kind: KindCounter, Help: "Plan/apply/reset commits.", Labels: []string{"result"}},
		{Name: MetricHTTPRequestsTotal, Kind: KindCounter, Help: "Management HTTP requests.", Labels: []string{"code", "route"}},
		{Name: MetricBuildInfo, Kind: KindGauge, Help: "Build metadata.", Labels: []string{"version", "commit"}},
		{Name: MetricAuthFailTotal, Kind: KindCounter, Help: "Community and USM authentication failures.", Labels: []string{"version"}},
		{Name: MetricTelemetryDropped, Kind: KindCounter, Help: "Telemetry samples dropped under policy or cardinality.", Labels: []string{"reason"}},
		{Name: MetricListenersBound, Kind: KindGauge, Help: "Listener bind state by component (1 bound, 0 enabled-but-unbound; omitted if off).", Labels: []string{"component"}},
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Name < defs[j].Name })
	for i := range defs {
		defs[i].Labels = append([]string(nil), defs[i].Labels...)
		sort.Strings(defs[i].Labels)
	}
	return defs
}

// Events returns the frozen structured-log event catalog.
func Events() []EventDef {
	names := []string{
		EventSNMPPDU, EventSNMPTrap, EventStateApply, EventStateReset,
		EventAuthFailure, EventHTTPRequest,
	}
	out := make([]EventDef, len(names))
	for i, n := range names {
		out[i] = EventDef{Name: n, Fields: append([]string(nil), EventFields...)}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LookupMetric returns the catalog definition for name.
func LookupMetric(name string) (MetricDef, bool) {
	def, ok := metricIndex[name]
	return def, ok
}

var metricIndex = func() map[string]MetricDef {
	defs := Metrics()
	m := make(map[string]MetricDef, len(defs))
	for _, d := range defs {
		m[d.Name] = d
	}
	return m
}()

// Catalog returns the versioned document.
func Catalog() Document {
	return Document{
		ID:              CatalogID,
		Version:         "v1alpha1",
		AllowedLabels:   append([]string(nil), AllowedLabels...),
		ForbiddenLabels: append([]string(nil), ForbiddenLabels...),
		Metrics:         Metrics(),
		Events:          Events(),
	}
}

// RenderCatalog is the generated JSON artifact.
func RenderCatalog() ([]byte, error) {
	b, err := json.MarshalIndent(Catalog(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
