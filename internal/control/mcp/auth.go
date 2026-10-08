package mcp

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/auth"
	"github.com/hilather/go-lab-snmp/internal/capabilities"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
)

const (
	defaultRequestsPerSecond = 32
	defaultBurst             = 64
)

func actorOf(p auth.Principal) app.Actor {
	return app.Actor{
		ID:        p.ID,
		Class:     p.Class,
		Role:      p.Role,
		Scopes:    append([]string(nil), p.Scopes...),
		Transport: "mcp",
	}
}

// fixedActor re-authenticates the startup bearer on every call.
// The caller's FixedActor is an identity anchor, not a scope cache, and is never mutated.
// A pin with no verifier keeps the startup snapshot.
// A secret that no longer authenticates returns no actor.
// On success the actor is the live principal for that secret, which may
// be a different id than the one recorded at process start.
func (s *Server) fixedActor() (app.Actor, bool) {
	if s == nil || s.cfg.FixedActor == nil {
		return app.Actor{}, false
	}
	if s.cfg.Auth != nil {
		p, err := s.cfg.Auth.AuthenticateBearer(s.cfg.StdioSecret)
		if err != nil {
			return app.Actor{}, false
		}
		return actorOf(p), true
	}
	out := *s.cfg.FixedActor
	if out.Transport == "" {
		out.Transport = "mcp"
	}
	return out, true
}

func (s *Server) authenticate(r *http.Request) (app.Actor, error) {
	if s.cfg.Auth == nil {
		return app.Actor{}, domainerr.Unauthenticated("authentication required")
	}
	h := strings.TrimSpace(r.Header.Get(headerAuthorization))
	if h != "" && strings.HasPrefix(strings.ToLower(h), "basic ") {
		return app.Actor{}, domainerr.Unauthenticated("MCP accepts bearer tokens only")
	}
	if s.cfg.FixedActor != nil && h == "" {
		out, ok := s.fixedActor()
		if !ok {
			return app.Actor{}, domainerr.Unauthenticated("authentication required")
		}
		return out, nil
	}
	p, err := s.cfg.Auth.Authenticate(auth.Request{
		Authorization: h,
		RemoteAddr:    r.RemoteAddr,
	})
	if err != nil {
		return app.Actor{}, err
	}
	return actorOf(p), nil
}

func (s *Server) authorizeResource(actor app.Actor, uri string) error {
	if s.cfg.Auth == nil {
		return domainerr.Unauthenticated("authentication required")
	}
	cap, ok := lookupResource(uri)
	if !ok {
		return domainerr.NotFound("not found")
	}
	return auth.AuthorizeScopes(actor.Scopes, cap.RequiredScopes)
}

func lookupResource(uri string) (capabilities.Capability, bool) {
	if c, ok := capabilities.LookupResource(uri); ok {
		return c, true
	}
	switch {
	case strings.HasPrefix(uri, "labsnmp://maps/"):
		name := strings.TrimPrefix(uri, "labsnmp://maps/")
		if name == "" || strings.Contains(name, "/") {
			return capabilities.Capability{}, false
		}
		return capabilities.Lookup(capabilities.MapsGet)
	case strings.HasPrefix(uri, "labsnmp://traps/"):
		id := strings.TrimPrefix(uri, "labsnmp://traps/")
		if id == "" || strings.Contains(id, "/") {
			return capabilities.Capability{}, false
		}
		return capabilities.Lookup(capabilities.TrapsGet)
	default:
		return capabilities.Capability{}, false
	}
}

func (s *Server) authorizeTool(actor app.Actor, name string) error {
	if s.cfg.Auth == nil {
		return domainerr.Unauthenticated("authentication required")
	}
	caps := capabilities.LookupTool(name)
	if len(caps) == 0 {
		return domainerr.Forbidden("unknown tool")
	}
	return auth.AuthorizeScopes(actor.Scopes, caps[0].RequiredScopes)
}

type limiter struct {
	disabled bool
	rate     float64
	burst    float64
	mu       sync.Mutex
	buckets  map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(rate, burst float64) *limiter {
	if rate < 0 {
		return &limiter{disabled: true}
	}
	if rate == 0 {
		rate = float64(defaultRequestsPerSecond)
	}
	if burst == 0 {
		burst = float64(defaultBurst)
	}
	return &limiter{rate: rate, burst: burst, buckets: map[string]*bucket{}}
}

func (l *limiter) allow(remote string) error {
	if l == nil || l.disabled {
		return nil
	}
	key := remote
	if host, _, err := net.SplitHostPort(remote); err == nil {
		key = host
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evictIdleLocked(now)
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return domainerr.RateLimited("too many management requests")
	}
	b.tokens--
	return nil
}

func (l *limiter) evictIdleLocked(now time.Time) {
	if l == nil || len(l.buckets) == 0 {
		return
	}
	idleFor := 30 * time.Second
	if l.rate > 0 {
		refill := time.Duration(float64(time.Second) * (l.burst / l.rate) * 4)
		if refill > idleFor {
			idleFor = refill
		}
	}
	for k, b := range l.buckets {
		if now.Sub(b.last) > idleFor {
			delete(l.buckets, k)
		}
	}
}
