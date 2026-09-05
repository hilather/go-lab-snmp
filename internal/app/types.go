package app

import (
	"encoding/json"
	"time"

	"github.com/hilather/go-lab-snmp/internal/buildinfo"
	"github.com/hilather/go-lab-snmp/internal/capabilities"
	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/store"
)

// Actor is the caller identity recorded on audit and used for scope checks.
type Actor struct {
	ID        string
	Class     string
	Role      string
	Scopes    []string
	Transport string
}

// ChangeIn is the shared plan/apply envelope.
type ChangeIn struct {
	ExpectedRevision model.Revision
	IdempotencyKey   string
	Reason           string
	Force            bool
	Operations       []model.Operation
}

// ValidateIn validates a candidate document and/or operations.
type ValidateIn struct {
	State      *model.State
	Operations []model.Operation
}

// ResetIn is the privileged bootstrap reread. expectedRevision is not required.
type ResetIn struct {
	Reason string
}

// Plan is the dry-run result of validate/plan (and the body of apply).
type Plan struct {
	PreviousRevision  model.Revision
	CandidateRevision model.Revision
	Drifted           bool
	Diff              []DiffEntry
	Warnings          []Warning
	Operations        []model.Operation
}

// ApplyResult is a committed mutation result.
type ApplyResult struct {
	Plan
	Applied         bool
	Generation      model.Generation
	RuntimeRevision model.Revision
	StoreGeneration uint64
}

// ExportFormat selects canonical YAML or JSON. Comments are never preserved.
type ExportFormat string

const (
	ExportYAML ExportFormat = "yaml"
	ExportJSON ExportFormat = "json"
)

// Export is canonical desired state plus drift material.
type Export struct {
	Format            ExportFormat
	Body              []byte
	Revision          model.Revision
	BootstrapRevision model.Revision
	Drifted           bool
	HumanDiff         string
}

// StateView is GET /v1/state. Canonical is a copy; mutating it cannot
// affect the live snapshot.
type StateView struct {
	BootstrapRevision model.Revision
	RuntimeRevision   model.Revision
	Generation        model.Generation
	StoreGeneration   uint64
	Drifted           bool
	LoadedAt          time.Time
	Canonical         *model.State
}

// Status is the agent-readable process DTO.
type Status struct {
	Ready     bool
	Revisions RevisionView
	Listeners []ListenerStatus
	HostTime  time.Time
	Warnings  []Warning
}

// RevisionView is bootstrap vs runtime identity.
type RevisionView struct {
	BootstrapRevision model.Revision
	RuntimeRevision   model.Revision
	Generation        model.Generation
	StoreGeneration   uint64
	Drifted           bool
	LoadedAt          time.Time
}

// ListenerStatus is one bound (or configured) listener.
type ListenerStatus struct {
	Name    string
	Address string
}

// Warning is a bounded, stable-coded note.
type Warning struct {
	Code    string
	Message string
}

// HealthFacts is the input to Status.Ready / observability.Evaluate.
type HealthFacts = observability.Facts

// DiffEntry is one canonical-path change. Paths are sorted in plans.
type DiffEntry struct {
	Path   string          `json:"path"`
	Op     string          `json:"op"`
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`
}

// CapabilityView lists frozen capability names for discovery.
type CapabilityView struct {
	Capabilities []CapabilityInfo
}

// CapabilityInfo is one registry discovery row (tool name, or health.* id).
type CapabilityInfo struct {
	Name        string
	Version     string
	Description string
	Mutating    bool
	Idempotent  bool
}

// FeatureApplyLive and FeatureApplyResetOnly are the only apply values.
const (
	FeatureApplyLive      = capabilities.FeatureApplyLive
	FeatureApplyResetOnly = capabilities.FeatureApplyResetOnly
)

// Feature is one frozen live vs reset-only row from docs/04 / K20.
type Feature = capabilities.Feature

// FeatureList is GET /v1/features.
type FeatureList struct {
	Items []Feature
}

// MapQueryIn is POST /v1/maps/{name}:query. PDU is get, getNext, or getBulk.
type MapQueryIn struct {
	PDU            string
	OIDs           []string
	NonRepeaters   int
	MaxRepetitions int
}

// MapQueryResult is overlay-aware simulated GET/GETNEXT/GETBULK bindings.
type MapQueryResult struct {
	Bindings []OIDResult
}

// PreviewIn is GET /v1/preview/get. Community or User is a YAML row id.
type PreviewIn struct {
	Community string
	User      string
	OID       string
}

// Stats is GET /v1/stats.
type Stats struct {
	Traps             store.TrapStats
	OverlayGeneration uint64
	Queries           int
}

// AuditQuery is GET /v1/audit. SEC-001 fills the ring.
type AuditQuery struct {
	Limit int
}

// AuditEvent is one in-memory audit row. SEC-001 owns the fields.
type AuditEvent struct {
	ID string `json:"id"`
}

// AuditList is GET /v1/audit.
type AuditList struct {
	Events []AuditEvent
}

// MapList is GET /v1/maps.
type MapList struct {
	Items []model.MapSpec
}

// CommunityList is GET /v1/communities.
type CommunityList struct {
	Items []model.CommunitySpec
}

// UserList is GET /v1/users. Secret bytes never appear; paths may.
type UserList struct {
	Items []model.UserSpec
}

// OIDSetIn is REST/MCP oids:set. Body is a single {oid, value}.
type OIDSetIn struct {
	Map   string
	OID   string
	Value mibtree.Value
}

// OIDGetIn is REST/MCP oids:get / preview get against a named map.
type OIDGetIn struct {
	Map string
	OID string
}

// OIDResult is one overlay-aware GET of a compiled leaf.
type OIDResult struct {
	OID       string
	Value     mibtree.Value
	Exception string
	Overlay   bool
}

// Page is opaque-cursor pagination. Empty cursor starts at the beginning.
type Page struct {
	Limit  int
	Cursor string
}

// QueryList is GET /v1/queries.
type QueryList struct {
	Items []store.Query
}

// TrapList is GET /v1/traps.
type TrapList struct {
	Items []store.TrapRecord
	Next  string
}

// TrapWaitIn is POST /v1/traps:wait.
type TrapWaitIn struct {
	Filter  store.TrapFilter
	Timeout time.Duration
}

// Version is buildinfo.Info.
type Version = buildinfo.Info
