package store

import (
	"sync"

	"github.com/hilather/go-lab-snmp/internal/mibtree"
)

// Pair is one overlay write. SNMP SET phase 2 applies a slice in order.
type Pair struct {
	OID   string
	Value mibtree.Value
}

// Overlay is a per-map oid→value copy-on-write layer over bootstrap trees.
// GET reads overlay first, then bootstrap, except valueFrom: uptime.
type Overlay struct {
	mu   sync.Mutex
	maps map[string]map[string]mibtree.Value
	gen  uint64
}

// NewOverlay returns an empty overlay (generation 0).
func NewOverlay() *Overlay {
	return &Overlay{maps: make(map[string]map[string]mibtree.Value)}
}

// Get returns the overlay value for mapName/oid, if any.
func (o *Overlay) Get(mapName, oid string) (mibtree.Value, bool) {
	if o == nil {
		return mibtree.Value{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	m := o.maps[mapName]
	if m == nil {
		return mibtree.Value{}, false
	}
	v, ok := m[oid]
	if !ok {
		return mibtree.Value{}, false
	}
	return cloneValue(v), true
}

// Set writes one oid and increments storeGeneration.
func (o *Overlay) Set(mapName, oid string, v mibtree.Value) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.putLocked(mapName, oid, v)
	o.gen++
}

// SetAll applies every pair then increments storeGeneration once.
func (o *Overlay) SetAll(mapName string, pairs []Pair) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, p := range pairs {
		o.putLocked(mapName, p.OID, p.Value)
	}
	o.gen++
}

func (o *Overlay) putLocked(mapName, oid string, v mibtree.Value) {
	if o.maps == nil {
		o.maps = make(map[string]map[string]mibtree.Value)
	}
	m := o.maps[mapName]
	if m == nil {
		m = make(map[string]mibtree.Value)
		o.maps[mapName] = m
	}
	m[oid] = cloneValue(v)
}

// Clear drops every overlay write and increments storeGeneration.
func (o *Overlay) Clear() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.maps = make(map[string]map[string]mibtree.Value)
	o.gen++
}

// Generation is the process-local overlay counter (SET / oids:set / reset).
func (o *Overlay) Generation() uint64 {
	if o == nil {
		return 0
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.gen
}

func cloneValue(v mibtree.Value) mibtree.Value {
	out := v
	if v.Bytes != nil {
		out.Bytes = append([]byte(nil), v.Bytes...)
	}
	if v.OID != nil {
		out.OID = append(mibtree.OID(nil), v.OID...)
	}
	return out
}
