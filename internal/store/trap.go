package store

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/oklog/ulid/v2"
)

const (
	DefaultMaxMessages = 1000
	DefaultMaxBytes    = int64(16 << 20)
	DefaultMaxWait     = 60 * time.Second
)

// VarBind is one parsed trap/inform binding. Identity secrets never appear here.
type VarBind struct {
	OID      string
	Type     string
	Integer  int64
	Unsigned uint64
	Bytes    []byte
	OIDValue string
}

// TrapRecord is one inbox entry (docs/03). Community/User are YAML row names.
type TrapRecord struct {
	ID              string
	ReceivedAt      time.Time
	Version         string
	PDUType         string
	Community       string
	User            string
	RemoteAddr      string
	Enterprise      string
	NotificationOID string
	VarBinds        []VarBind
	Raw             []byte
	ParseWarning    string
	Size            int64 // byte contribution; 0 means len(Raw)
}

// TrapFilter selects Wait/List records. Empty fields are wildcards.
type TrapFilter struct {
	Version         string
	PDUType         string
	Community       string
	User            string
	NotificationOID string
	Since           time.Time
}

// ListQuery pages oldest-first records.
type ListQuery struct {
	Limit  int
	After  string
	Filter TrapFilter
}

// ListResult is one page of trap records.
type ListResult struct {
	Items []TrapRecord
	Next  string
}

// TrapStats is a point-in-time inbox snapshot.
type TrapStats struct {
	Messages   int
	Bytes      int64
	Generation uint64
	Dropped    int64
}

// TrapPolicy is the live ring cap (replaceTrapStorePolicy).
type TrapPolicy struct {
	MaxMessages int
	MaxBytes    int64
	FullPolicy  string
	MaxWait     time.Duration
}

type waitResult struct {
	rec *TrapRecord
	err error
}

type waiter struct {
	filter TrapFilter
	ch     chan waitResult
	done   bool
}

// TrapRing is the ephemeral trap/inform inbox. Reset and restart wipe it.
type TrapRing struct {
	mu      sync.Mutex
	recs    []TrapRecord
	bytes   int64
	policy  TrapPolicy
	gen     uint64
	dropped int64
	waiters []*waiter
	now     func() time.Time
	entropy io.Reader
}

// NewTrapRing allocates an empty inbox. Zero caps become 1.0 defaults.
func NewTrapRing(p TrapPolicy) *TrapRing {
	return &TrapRing{
		recs:    make([]TrapRecord, 0),
		policy:  normalizePolicy(p),
		now:     time.Now,
		entropy: ulid.DefaultEntropy(),
	}
}

// SetClock replaces the time source (tests).
func (r *TrapRing) SetClock(now func() time.Time) {
	if r == nil || now == nil {
		return
	}
	r.mu.Lock()
	r.now = now
	r.mu.Unlock()
}

func normalizePolicy(p TrapPolicy) TrapPolicy {
	if p.MaxMessages < 1 {
		p.MaxMessages = DefaultMaxMessages
	}
	if p.MaxBytes < 1 {
		p.MaxBytes = DefaultMaxBytes
	}
	switch p.FullPolicy {
	case model.FullPolicyReject, model.FullPolicyEvictOldest:
	default:
		p.FullPolicy = model.FullPolicyEvictOldest
	}
	if p.MaxWait <= 0 {
		p.MaxWait = DefaultMaxWait
	}
	return p
}

func (r *TrapRing) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// Insert assigns a ULID when id is empty. A single record larger than
// maxBytes is rejected without wiping the inbox.
func (r *TrapRing) Insert(rec TrapRecord) (string, error) {
	if r == nil {
		return "", domainerr.Internal("trap store is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.clock()
	if rec.ReceivedAt.IsZero() {
		rec.ReceivedAt = now
	}
	if rec.ID == "" {
		id, err := ulid.New(ulid.Timestamp(rec.ReceivedAt), r.entropy)
		if err != nil {
			return "", domainerr.Internal("trap id: " + err.Error())
		}
		rec.ID = id.String()
	}
	size := rec.Size
	if size < 1 {
		size = int64(len(rec.Raw))
	}
	if size < 1 {
		size = 1
	}
	rec.Size = size
	rec = cloneRecord(rec)

	if size > r.policy.MaxBytes {
		r.dropped++
		return "", domainerr.ValidationFailed("trap exceeds maxBytes")
	}

	switch r.policy.FullPolicy {
	case model.FullPolicyReject:
		if len(r.recs) >= r.policy.MaxMessages || r.bytes+size > r.policy.MaxBytes {
			r.dropped++
			return "", domainerr.ValidationFailed("trap store is full")
		}
	default:
		for len(r.recs) > 0 && (len(r.recs) >= r.policy.MaxMessages || r.bytes+size > r.policy.MaxBytes) {
			r.evictOldestLocked()
		}
		if len(r.recs) >= r.policy.MaxMessages || r.bytes+size > r.policy.MaxBytes {
			r.dropped++
			return "", domainerr.ValidationFailed("trap store is full")
		}
	}

	r.recs = append(r.recs, rec)
	r.bytes += size
	r.gen++
	r.notifyLocked(rec)
	return rec.ID, nil
}

func (r *TrapRing) evictOldestLocked() {
	if len(r.recs) == 0 {
		return
	}
	old := r.recs[0]
	r.recs = r.recs[1:]
	r.bytes -= old.Size
	if r.bytes < 0 {
		r.bytes = 0
	}
}

func (r *TrapRing) notifyLocked(rec TrapRecord) {
	if len(r.waiters) == 0 {
		return
	}
	keep := r.waiters[:0]
	for _, w := range r.waiters {
		if w == nil || w.done {
			continue
		}
		if !matchFilter(rec, w.filter) {
			keep = append(keep, w)
			continue
		}
		w.done = true
		cloned := cloneRecord(rec)
		select {
		case w.ch <- waitResult{rec: &cloned}:
		default:
		}
	}
	r.waiters = keep
}

// Get returns a copy of the record, or not_found.
func (r *TrapRing) Get(id string) (*TrapRecord, error) {
	if r == nil {
		return nil, domainerr.NotFound("trap not found")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.recs {
		if r.recs[i].ID == id {
			cloned := cloneRecord(r.recs[i])
			return &cloned, nil
		}
	}
	return nil, domainerr.NotFound("trap not found")
}

// Raw returns the retained datagram, or not_found.
func (r *TrapRing) Raw(id string) ([]byte, error) {
	rec, err := r.Get(id)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), rec.Raw...), nil
}

// List returns oldest-first copies matching q.
func (r *TrapRing) List(q ListQuery) (ListResult, error) {
	if r == nil {
		return ListResult{}, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var items []TrapRecord
	seenAfter := q.After == ""
	for i := range r.recs {
		rec := r.recs[i]
		if !seenAfter {
			if rec.ID == q.After {
				seenAfter = true
			}
			continue
		}
		if !matchFilter(rec, q.Filter) {
			continue
		}
		items = append(items, cloneRecord(rec))
		if q.Limit > 0 && len(items) >= q.Limit {
			break
		}
	}
	next := ""
	if q.Limit > 0 && len(items) == q.Limit {
		next = items[len(items)-1].ID
	}
	return ListResult{Items: items, Next: next}, nil
}

// Wait returns an existing match, a later insert, wait_timeout, or store_wiped.
func (r *TrapRing) Wait(ctx context.Context, filter TrapFilter, timeout time.Duration) (*TrapRecord, error) {
	if r == nil {
		return nil, domainerr.Internal("trap store is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	if timeout <= 0 || timeout > r.policy.MaxWait {
		timeout = r.policy.MaxWait
	}
	if rec := r.firstMatchLocked(filter); rec != nil {
		r.mu.Unlock()
		return rec, nil
	}
	w := &waiter{filter: filter, ch: make(chan waitResult, 1)}
	r.waiters = append(r.waiters, w)
	r.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		r.dropWaiter(w)
		fallback := ctx.Err()
		if fallback == context.DeadlineExceeded {
			fallback = domainerr.New(domainerr.CodeWaitTimeout, "wait timed out")
		}
		return takeWait(w, fallback)
	case <-timer.C:
		r.dropWaiter(w)
		return takeWait(w, domainerr.New(domainerr.CodeWaitTimeout, "wait timed out"))
	case res := <-w.ch:
		return res.rec, res.err
	}
}

func takeWait(w *waiter, fallback error) (*TrapRecord, error) {
	select {
	case res := <-w.ch:
		return res.rec, res.err
	default:
		return nil, fallback
	}
}

func (r *TrapRing) firstMatchLocked(filter TrapFilter) *TrapRecord {
	for i := range r.recs {
		if matchFilter(r.recs[i], filter) {
			cloned := cloneRecord(r.recs[i])
			return &cloned
		}
	}
	return nil
}

func (r *TrapRing) dropWaiter(w *waiter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if w.done {
		return
	}
	w.done = true
	keep := r.waiters[:0]
	for _, cur := range r.waiters {
		if cur != w {
			keep = append(keep, cur)
		}
	}
	r.waiters = keep
}

func (r *TrapRing) wipeLocked(err error) {
	r.recs = make([]TrapRecord, 0)
	r.bytes = 0
	r.gen++
	if len(r.waiters) == 0 {
		return
	}
	for _, w := range r.waiters {
		if w == nil || w.done {
			continue
		}
		w.done = true
		select {
		case w.ch <- waitResult{err: err}:
		default:
		}
	}
	r.waiters = nil
}

// Clear is POST traps:clear. Waiters receive store_wiped.
func (r *TrapRing) Clear() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.wipeLocked(domainerr.New(domainerr.CodeStoreWiped, "trap store wiped"))
}

// Wipe is process reset. Waiters receive store_wiped.
func (r *TrapRing) Wipe() {
	r.Clear()
}

// Generation is the process-local inbox counter (insert / wipe / replace).
func (r *TrapRing) Generation() uint64 {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.gen
}

// Stats is a snapshot of occupancy and drops.
func (r *TrapRing) Stats() TrapStats {
	if r == nil {
		return TrapStats{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return TrapStats{
		Messages:   len(r.recs),
		Bytes:      r.bytes,
		Generation: r.gen,
		Dropped:    r.dropped,
	}
}

// ReplaceCaps updates live caps and evicts until the inbox fits.
func (r *TrapRing) ReplaceCaps(maxMessages int, maxBytes int64, policy string) error {
	if r == nil {
		return domainerr.Internal("trap store is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policy = normalizePolicy(TrapPolicy{
		MaxMessages: maxMessages,
		MaxBytes:    maxBytes,
		FullPolicy:  policy,
		MaxWait:     r.policy.MaxWait,
	})
	for len(r.recs) > 0 && (len(r.recs) > r.policy.MaxMessages || r.bytes > r.policy.MaxBytes) {
		r.evictOldestLocked()
	}
	r.gen++
	return nil
}

func matchFilter(rec TrapRecord, f TrapFilter) bool {
	if f.Version != "" && rec.Version != f.Version {
		return false
	}
	if f.PDUType != "" && rec.PDUType != f.PDUType {
		return false
	}
	if f.Community != "" && rec.Community != f.Community {
		return false
	}
	if f.User != "" && rec.User != f.User {
		return false
	}
	if f.NotificationOID != "" && rec.NotificationOID != f.NotificationOID {
		return false
	}
	if !f.Since.IsZero() && !rec.ReceivedAt.After(f.Since) {
		return false
	}
	return true
}

func cloneRecord(r TrapRecord) TrapRecord {
	out := r
	if r.Raw != nil {
		out.Raw = append([]byte(nil), r.Raw...)
	}
	if r.VarBinds != nil {
		out.VarBinds = make([]VarBind, len(r.VarBinds))
		for i := range r.VarBinds {
			out.VarBinds[i] = cloneVarBind(r.VarBinds[i])
		}
	}
	return out
}

func cloneVarBind(v VarBind) VarBind {
	out := v
	if v.Bytes != nil {
		out.Bytes = append([]byte(nil), v.Bytes...)
	}
	return out
}
