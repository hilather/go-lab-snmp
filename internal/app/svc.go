package app

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-lab-snmp/internal/audit"
	"github.com/hilather/go-lab-snmp/internal/buildinfo"
	"github.com/hilather/go-lab-snmp/internal/capabilities"
	"github.com/hilather/go-lab-snmp/internal/compiler"
	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
	"github.com/hilather/go-lab-snmp/internal/store"
	"github.com/hilather/go-lab-snmp/internal/testutil"
)

const (
	defaultIdempotencyMax = 256
	defaultAuditMax       = 128
)

// Options constructs an App.
type Options struct {
	Snapshots      *snapshot.Store
	Now            func() time.Time
	Clock          testutil.Clock
	BootstrapPath  string
	IdempotencyMax int
	AuditMax       int
	Auditor        audit.Sink
	Overlay        *store.Overlay
	Queries        *store.QueryRing
	Traps          *store.TrapRing
	// SNMPListenOverride is --snmp-listen (empty uses YAML). Flag wins on Reset.
	SNMPListenOverride string
	// TrapListenOverride is --trap-listen including off/none/-.
	TrapListenOverride string
	// MgmtListenOverride is --management-listen including off/none/-.
	MgmtListenOverride string
	Metrics            *observability.Registry
	Logger             *observability.Logger
}

// App is the process-local Service implementation.
type App struct {
	mu            sync.Mutex
	snaps         *snapshot.Store
	now           func() time.Time
	clock         testutil.Clock
	bootstrapPath string
	idemp         *idempCache
	audit         *audit.Fanout
	resetHooks    []func()
	applyHooks    []func()
	overlay       *store.Overlay
	queries       *store.QueryRing
	traps         *store.TrapRing
	snmpOverride  string
	trapOverride  string
	mgmtOverride  string

	snmpRebind func(addr string) error
	trapRebind func(addr string) error
	httpRebind func(addr string) error

	metrics *observability.Registry
	logger  *observability.Logger

	healthMu sync.Mutex
	health   func() observability.Facts
}

var _ Service = (*App)(nil)

// New returns an App. A nil Snapshots becomes an empty snapshot.Store.
func New(opts Options) *App {
	if opts.Snapshots == nil {
		opts.Snapshots = snapshot.NewStore()
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now() }
	}
	if opts.Clock == nil {
		opts.Clock = testutil.SystemClock{}
	}
	if opts.Overlay == nil {
		opts.Overlay = store.NewOverlay()
	}
	if opts.Queries == nil {
		opts.Queries = store.NewQueryRing(store.DefaultQueryRing)
	}
	if opts.Traps == nil {
		p := store.TrapPolicy{}
		if snap := opts.Snapshots.Load(); snap != nil && snap.Canonical != nil {
			p.MaxMessages = snap.Canonical.Spec.Traps.MaxMessages
			p.MaxBytes = snap.Canonical.Spec.Traps.MaxBytes
			p.FullPolicy = snap.Canonical.Spec.Traps.FullPolicy
			p.MaxWait = snap.Canonical.Spec.Traps.MaxWait
		}
		opts.Traps = store.NewTrapRing(p)
	}
	idempMax := opts.IdempotencyMax
	if idempMax <= 0 {
		idempMax = defaultIdempotencyMax
	}
	auditMax := opts.AuditMax
	if auditMax <= 0 {
		auditMax = defaultAuditMax
	}
	return &App{
		snaps:         opts.Snapshots,
		now:           opts.Now,
		clock:         opts.Clock,
		bootstrapPath: opts.BootstrapPath,
		idemp:         newIdempCache(idempMax),
		audit:         audit.NewFanout(auditMax, opts.Auditor),
		overlay:       opts.Overlay,
		queries:       opts.Queries,
		traps:         opts.Traps,
		snmpOverride:  opts.SNMPListenOverride,
		trapOverride:  opts.TrapListenOverride,
		mgmtOverride:  opts.MgmtListenOverride,
		metrics:       opts.Metrics,
		logger:        opts.Logger,
	}
}

// Boot loads bootstrap YAML, compiles a snapshot, and installs it.
func Boot(ctx context.Context, opts Options) (*App, error) {
	_ = ctx
	if opts.BootstrapPath == "" {
		return nil, domainerr.ValidationFailed("bootstrap path is required",
			domainerr.FieldViolation{Path: "bootstrapPath", Code: "required", Message: "bootstrap path is required"})
	}
	st, err := config.LoadFile(opts.BootstrapPath)
	if err != nil {
		return nil, asDomain(err)
	}
	snap, err := compiler.Compile(st, compiler.CompileOpts{
		Clock:   opts.Clock,
		BaseDir: filepath.Dir(opts.BootstrapPath),
	})
	if err != nil {
		return nil, asDomain(err)
	}
	if opts.Snapshots == nil {
		opts.Snapshots = snapshot.NewStore()
	}
	opts.Snapshots.InstallBootstrap(snap)
	if opts.Overlay == nil {
		opts.Overlay = store.NewOverlay()
	}
	if opts.Queries == nil {
		opts.Queries = store.NewQueryRing(store.DefaultQueryRing)
	}
	if opts.Traps == nil {
		opts.Traps = store.NewTrapRing(store.TrapPolicy{
			MaxMessages: snap.Canonical.Spec.Traps.MaxMessages,
			MaxBytes:    snap.Canonical.Spec.Traps.MaxBytes,
			FullPolicy:  snap.Canonical.Spec.Traps.FullPolicy,
			MaxWait:     snap.Canonical.Spec.Traps.MaxWait,
		})
	}
	return New(opts), nil
}

// BootstrapDir is the directory of the bootstrap YAML (secretFile fallback).
func (s *App) BootstrapDir() string {
	if s == nil || s.bootstrapPath == "" {
		return ""
	}
	return filepath.Dir(s.bootstrapPath)
}

// Snapshots is the live config pointer the agent re-reads per packet.
func (s *App) Snapshots() *snapshot.Store {
	if s == nil {
		return nil
	}
	return s.snaps
}

// Active is the live snapshot, or nil.
func (s *App) Active() *snapshot.Snapshot {
	if s == nil || s.snaps == nil {
		return nil
	}
	return s.snaps.Load()
}

// Overlay is the process-local SET / oids:set layer.
func (s *App) Overlay() *store.Overlay {
	if s == nil {
		return nil
	}
	return s.overlay
}

// Queries is the process PDU summary ring.
func (s *App) Queries() *store.QueryRing {
	if s == nil {
		return nil
	}
	return s.queries
}

// Traps is the process trap inbox.
func (s *App) Traps() *store.TrapRing {
	if s == nil {
		return nil
	}
	return s.traps
}

// Close is a no-op placeholder for Boot callers.
func (s *App) Close() {}

// SetSNMPRebind installs the bind-new-first hook for the agent listener.
func (s *App) SetSNMPRebind(fn func(addr string) error) {
	if s == nil {
		return
	}
	s.snmpRebind = fn
}

// SetTrapRebind installs the bind-new-first hook for the trap listener.
func (s *App) SetTrapRebind(fn func(addr string) error) {
	if s == nil {
		return
	}
	s.trapRebind = fn
}

// SetHTTPRebind installs the management HTTP bind-new-first hook.
func (s *App) SetHTTPRebind(fn func(addr string) error) {
	if s == nil {
		return
	}
	s.httpRebind = fn
}

// SetLogger replaces the structured logger (serve reapplies YAML logLevel).
func (s *App) SetLogger(l *observability.Logger) {
	if s == nil {
		return
	}
	s.logger = l
}

// SetHealth installs live listener facts for Status.Ready / Evaluate.
func (s *App) SetHealth(fn func() observability.Facts) {
	if s == nil {
		return
	}
	s.healthMu.Lock()
	s.health = fn
	s.healthMu.Unlock()
}

// HealthFacts is the input to observability.Evaluate.
func (s *App) HealthFacts() observability.Facts {
	if s == nil {
		return observability.Facts{}
	}
	s.healthMu.Lock()
	fn := s.health
	s.healthMu.Unlock()
	snapUp := s.Active() != nil
	if fn != nil {
		f := fn()
		f.SnapshotUp = snapUp
		return f
	}
	return observability.Facts{SnapshotUp: snapUp}
}

// OnReset registers a hook fired after a successful Reset (outside the mutex).
func (s *App) OnReset(fn func()) {
	if s == nil || fn == nil {
		return
	}
	s.mu.Lock()
	s.resetHooks = append(s.resetHooks, fn)
	s.mu.Unlock()
}

// OnApply registers a hook fired after a successful Apply (outside the mutex).
func (s *App) OnApply(fn func()) {
	if s == nil || fn == nil {
		return
	}
	s.mu.Lock()
	s.applyHooks = append(s.applyHooks, fn)
	s.mu.Unlock()
}

func (s *App) requireCtx(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func (s *App) active() (*snapshot.Snapshot, error) {
	if s == nil || s.snaps == nil {
		return nil, domainerr.Internal("no snapshot store")
	}
	snap := s.snaps.Load()
	if snap == nil {
		return nil, domainerr.Internal("no active snapshot")
	}
	return snap, nil
}

func (s *App) Version(ctx context.Context, actor Actor) (*buildinfo.Info, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	info := buildinfo.Current()
	return &info, nil
}

func (s *App) Capabilities(ctx context.Context, actor Actor) (*CapabilityView, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	src := capabilities.DiscoveryList()
	out := make([]CapabilityInfo, 0, len(src))
	for _, d := range src {
		out = append(out, CapabilityInfo{
			Name: d.Name, Version: d.Version, Description: d.Description,
			Mutating: d.Mutating, Idempotent: d.Idempotent,
		})
	}
	return &CapabilityView{Capabilities: out}, nil
}

func (s *App) Features(ctx context.Context, actor Actor) (*FeatureList, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	return &FeatureList{Items: Features()}, nil
}

func (s *App) Stats(ctx context.Context, actor Actor) (*Stats, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	out := &Stats{OverlayGeneration: s.storeGeneration()}
	if s.traps != nil {
		out.Traps = s.traps.Stats()
	}
	if s.queries != nil {
		out.Queries = s.queries.Len()
	}
	return out, nil
}

func (s *App) ConfigSchema(ctx context.Context, actor Actor) ([]byte, error) {
	if err := s.requireCtx(ctx); err != nil {
		return nil, err
	}
	_ = actor
	b, err := config.SchemaBytes()
	if err != nil {
		return nil, domainerr.Internal("schema unavailable")
	}
	return b, nil
}

func asDomain(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := domainerr.As(err); ok {
		return err
	}
	return domainerr.Internal(err.Error())
}

func managementOff(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "none", "-":
		return true
	default:
		return false
	}
}

func listenOff(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "none", "-":
		return true
	default:
		return false
	}
}

func listenAddress(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && !listenOff(s)
}

func effectiveSNMP(override, yamlAddr string, enabled bool) string {
	switch {
	case listenOff(override):
		return ""
	case listenAddress(override):
		return strings.TrimSpace(override)
	case !enabled:
		return ""
	default:
		return yamlAddr
	}
}

func effectiveTrap(override, yamlAddr string, enabled bool) string {
	return effectiveSNMP(override, yamlAddr, enabled)
}

func effectiveMgmt(override, yamlAddr string) string {
	if override != "" {
		if managementOff(override) {
			return ""
		}
		return override
	}
	return yamlAddr
}
