package app

import (
	"encoding/json"
	"time"

	"github.com/hilather/go-lab-snmp/internal/buildinfo"
	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
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

// DiffEntry is one canonical-path change. Paths are sorted in plans.
type DiffEntry struct {
	Path   string          `json:"path"`
	Op     string          `json:"op"`
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`
}

// FeatureApplyLive and FeatureApplyResetOnly are the only apply values.
const (
	FeatureApplyLive      = "live"
	FeatureApplyResetOnly = "reset-only"
)

// Feature is one frozen live vs reset-only row from docs/04 / K20.
type Feature struct {
	ID    string `json:"id"`
	Apply string `json:"apply"`
	Path  string `json:"path"`
}

// FeatureList is GET /v1/features.
type FeatureList struct {
	Items []Feature
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
