package store

import "sync"

// DefaultQueryRing is last-N PDU summaries for GET /v1/queries. Not a YAML key.
const DefaultQueryRing = 256

// Query is one agent PDU summary. Identity is the community/user row name
// (never the community wire string or USM keys).
type Query struct {
	Type        string
	Identity    string
	Decision    string
	ErrorStatus int32
}

// QueryRing is a bounded ring of recent agent decisions.
type QueryRing struct {
	mu   sync.Mutex
	buf  []Query
	head int
	len  int
	cap  int
}

// NewQueryRing allocates a ring. n < 1 uses DefaultQueryRing.
func NewQueryRing(n int) *QueryRing {
	if n < 1 {
		n = DefaultQueryRing
	}
	return &QueryRing{buf: make([]Query, n), cap: n}
}

// Insert appends q, evicting the oldest when full.
func (r *QueryRing) Insert(q Query) {
	if r == nil || r.cap < 1 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.buf == nil {
		r.buf = make([]Query, r.cap)
	}
	idx := (r.head + r.len) % r.cap
	if r.len == r.cap {
		r.buf[r.head] = q
		r.head = (r.head + 1) % r.cap
		return
	}
	r.buf[idx] = q
	r.len++
}

// List returns oldest-first copies.
func (r *QueryRing) List() []Query {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Query, r.len)
	for i := 0; i < r.len; i++ {
		out[i] = r.buf[(r.head+i)%r.cap]
	}
	return out
}

// Len is the number of stored summaries.
func (r *QueryRing) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.len
}

// Clear drops every summary.
func (r *QueryRing) Clear() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.head = 0
	r.len = 0
}
