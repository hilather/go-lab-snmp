package rest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/auth"
	"github.com/hilather/go-lab-snmp/internal/capabilities"
	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/observability"
)

const (
	DefaultAddr              = config.DefaultMgmtAddress
	DefaultMaxBodyBytes      = config.DefaultBodyLimit
	DefaultRequestTimeout    = 30 * time.Second
	DefaultReadHeaderTimeout = 5 * time.Second
	DefaultReadTimeout       = 30 * time.Second
	DefaultMaxConcurrent     = 256
	DefaultRequestsPerSecond = 32
	DefaultBurst             = 64
	headerRequestID          = "X-Request-ID"
	headerIdempotency        = "Idempotency-Key"
	headerIfMatch            = "If-Match"
	headerExpected           = "X-LabSNMP-Expected-Revision"
	headerRevision           = "X-LabSNMP-Revision"
	headerAllow              = "Allow"
	requestURNPrefix         = "urn:labsnmp:request:"
	// managementDrainTimeout bounds the background drain of a management
	// server that has stopped accepting. Leftover connections (long-poll
	// traps:wait, SSE) are closed when the drain exceeds it.
	managementDrainTimeout = 5 * time.Second
)

// Config constructs a management HTTP server.
type Config struct {
	Addr              string
	Service           app.Service
	AllowedOrigins    []string
	Live              func() bool
	Ready             func() bool
	MaxBodyBytes      int64
	RequestTimeout    time.Duration
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	MaxConcurrent     int
	RatePerSec        float64
	RateBurst         float64
	PublicMetrics     bool
	Auth              *auth.Verifier
	Sessions          *auth.Store
	CookieSecure      bool
	Metrics           *observability.Registry
	Logger            *observability.Logger
	UI                http.Handler
	UIEnabled         func() bool
	Mounts            map[string]http.Handler
}

// Server is the stdlib net/http management listener.
type Server struct {
	cfg      Config
	svc      app.Service
	routes   []compiledRoute
	handler  http.Handler
	maxBody  int64
	timeout  time.Duration
	inflight chan struct{}
	rate     *limiter
	mounts   *http.ServeMux
	metrics  *observability.Registry
	logger   *observability.Logger

	sec  sync.RWMutex
	mu   sync.Mutex
	http *http.Server
	ln   net.Listener
	// drains are management servers Rebind detached. Each channel is
	// closed when that drain finishes, including Close after a timeout.
	// A slice under mu, not a WaitGroup: Add concurrent with Wait panics
	// once the counter has hit zero, and Rebind can start a drain while
	// Shutdown is waiting.
	drains []chan struct{}
	closed atomic.Bool
	addr   string
}

// New builds a Server. Routes come from the frozen capability registry.
func New(cfg Config) (*Server, error) {
	if cfg.Service == nil {
		return nil, errors.New("rest: Service is required")
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = DefaultRequestTimeout
	}
	n := cfg.MaxConcurrent
	if n <= 0 {
		n = DefaultMaxConcurrent
	}
	if cfg.Sessions == nil {
		cfg.Sessions = auth.NewStore(auth.DefaultSessionConfig())
	}
	if cfg.Auth != nil {
		sessions := cfg.Sessions
		cfg.Auth.OnIdentityChange(func() {
			if sessions != nil {
				sessions.Clear()
			}
		})
	}
	s := &Server{
		cfg:      cfg,
		svc:      cfg.Service,
		routes:   compileRoutes(capabilities.All()),
		maxBody:  maxBody,
		timeout:  timeout,
		inflight: make(chan struct{}, n),
		rate:     newLimiter(cfg.RatePerSec, cfg.RateBurst),
		addr:     cfg.Addr,
		metrics:  cfg.Metrics,
		logger:   cfg.Logger,
	}
	if appSvc, ok := s.svc.(*app.App); ok {
		appSvc.OnReset(s.reloadAuth)
		appSvc.OnApply(s.reloadAuth)
	}
	if len(cfg.Mounts) > 0 {
		mux := http.NewServeMux()
		for path, h := range cfg.Mounts {
			mux.Handle(path, h)
		}
		s.mounts = mux
	}
	s.handler = http.HandlerFunc(s.serveHTTP)
	return s, nil
}

// Handler returns the management mux. Safe for httptest.NewServer / ServeHTTP.
func (s *Server) Handler() http.Handler {
	return s.handler
}

// ListenAndServe binds Addr and serves until Shutdown.
func (s *Server) ListenAndServe() error {
	addr := s.cfg.Addr
	if addr == "" {
		addr = DefaultAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve serves on ln until Shutdown.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	if s.http != nil {
		s.mu.Unlock()
		_ = ln.Close()
		return errors.New("rest: server already started")
	}
	hs := s.newHTTPServer()
	s.http = hs
	s.ln = ln
	s.addr = ln.Addr().String()
	alreadyClosed := s.closed.Load()
	s.mu.Unlock()
	if alreadyClosed {
		_ = ln.Close()
		return nil
	}
	err := hs.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) newHTTPServer() *http.Server {
	rh := s.cfg.ReadHeaderTimeout
	if rh <= 0 {
		rh = DefaultReadHeaderTimeout
	}
	rt := s.cfg.ReadTimeout
	if rt <= 0 {
		rt = DefaultReadTimeout
	}
	return &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: rh,
		ReadTimeout:       rt,
		WriteTimeout:      s.cfg.WriteTimeout,
		MaxHeaderBytes:    1 << 16,
	}
}

// Rebind moves the management listener to addr. An empty addr stops
// accepting and clears the listener. The old server stops accepting
// before Rebind returns and drains in the background; Rebind does not
// wait for that drain. Bound is true on the new listener as soon as
// Listen succeeds, and false after an unbind (docs/09).
//
// A non-nil error means the previous listener is untouched. That is
// only a failed net.Listen on the new address.
func (s *Server) Rebind(addr string) error {
	if s == nil {
		return errors.New("rest: nil server")
	}
	if addr == "" {
		s.mu.Lock()
		s.closed.Store(true)
		hs := s.http
		ln := s.ln
		s.http = nil
		s.ln = nil
		s.addr = ""
		s.mu.Unlock()
		s.drainAsync(hs, ln)
		return nil
	}
	s.mu.Lock()
	cur := s.addr
	s.mu.Unlock()
	if addr == cur && s.Bound() {
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	hs := s.newHTTPServer()
	s.mu.Lock()
	old := s.http
	oldLn := s.ln
	s.http = hs
	s.ln = ln
	s.addr = ln.Addr().String()
	s.closed.Store(false)
	s.mu.Unlock()
	go func() { _ = hs.Serve(ln) }()
	s.drainAsync(old, oldLn)
	return nil
}

// drainAsync closes ln before it returns, then drains hs in the
// background for managementDrainTimeout. A timed-out drain calls Close
// so connections on a server that is no longer bound do not stay open.
//
// Shutdown sets inShutdown, closes listeners it is already tracking,
// and only then runs RegisterOnShutdown hooks via go f(). Waiting for
// that hook before closing ln keeps Serve from observing a raw close
// and returning "use of closed network connection" instead of
// ErrServerClosed. The raw listener is closed here as well because
// Serve may not have tracked it yet; a second close returns errClosing.
//
// net/http runs every onShutdown hook again on each later Shutdown.
// The hook only closes the signal, so a second close would panic an
// unrecovered goroutine. sync.Once makes that signal idempotent.
func (s *Server) drainAsync(hs *http.Server, ln net.Listener) {
	if hs == nil {
		if ln != nil {
			_ = ln.Close()
		}
		return
	}
	done := make(chan struct{})
	s.mu.Lock()
	s.drains = append(s.drains, done)
	s.mu.Unlock()

	started := make(chan struct{})
	var once sync.Once
	hs.RegisterOnShutdown(func() {
		once.Do(func() { close(started) })
	})
	ctx, cancel := context.WithTimeout(context.Background(), managementDrainTimeout)
	go func() {
		defer s.finishDrain(done)
		err := hs.Shutdown(ctx)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) {
			_ = hs.Close()
		}
	}()
	<-started
	if ln != nil {
		_ = ln.Close()
	}
}

// finishDrain drops done from the in-flight set, then closes it so a
// Shutdown that already copied the slice still wakes.
func (s *Server) finishDrain(done chan struct{}) {
	s.mu.Lock()
	for i, ch := range s.drains {
		if ch == done {
			s.drains = append(s.drains[:i], s.drains[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
	close(done)
}

// Bound reports whether a listener is accepting.
func (s *Server) Bound() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ln != nil && s.http != nil && !s.closed.Load()
}

// Shutdown closes the listener and waits for in-flight requests.
// It also waits for management servers that Rebind detached into a
// background drain. That wait is bounded by ctx. If ctx ends first,
// Shutdown returns ctx.Err() and does not wait out the drain.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closed.Store(true)
	s.mu.Lock()
	hs := s.http
	ln := s.ln
	s.mu.Unlock()
	var err error
	if hs != nil {
		err = hs.Shutdown(ctx)
	} else if ln != nil {
		err = ln.Close()
	}
	if werr := s.waitDrains(ctx); err == nil {
		err = werr
	}
	return err
}

// waitDrains waits for background drains already started when it is
// called. Drains that finish before the snapshot are already gone.
func (s *Server) waitDrains(ctx context.Context) error {
	s.mu.Lock()
	pending := append([]chan struct{}(nil), s.drains...)
	s.mu.Unlock()
	for _, done := range pending {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}
	return nil
}

// Addr returns the bound address after Serve, or the configured listen address.
// After Rebind(""), Bound is false and Addr is empty.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	if s.addr != "" {
		return s.addr
	}
	if s.closed.Load() {
		return ""
	}
	if s.cfg.Addr != "" {
		return s.cfg.Addr
	}
	return DefaultAddr
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
	w = sw
	reqID := requestID(r)
	w.Header().Set(headerRequestID, reqID)
	r.Header.Set(headerRequestID, reqID)
	instance := requestURNPrefix + reqID
	route := "other"
	defer func() {
		s.observeHTTP(route, sw.status(), start, reqID)
	}()

	if err := checkOrigin(r.Header.Get("Origin"), s.allowedOrigins()); err != nil {
		s.writeProblem(w, r, instance, err)
		return
	}
	if r.Method == http.MethodOptions {
		s.writeProblem(w, r, instance, domainerr.Forbidden("CORS is disabled"))
		return
	}

	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		s.writeProblem(w, r, instance, domainerr.RateLimited("too many concurrent management requests"))
		return
	}

	defer func() {
		if rec := recover(); rec != nil {
			s.writeProblem(w, r, instance, domainerr.Internal("internal error"))
		}
	}()

	if s.dispatchMount(w, r, instance) {
		return
	}

	rt, params, pathOK, methodOK := matchRoute(s.routes, r.Method, r.URL.Path)
	if pathOK {
		route = rt.binding.Path
	}
	// traps.wait is capped by spec.traps.maxWait (default 60s), not the
	// generic management request timeout.
	if s.timeout > 0 && (!pathOK || !methodOK || rt.cap.ID != capabilities.TrapsWait) {
		ctx, cancel := context.WithTimeout(r.Context(), s.timeout)
		defer cancel()
		r = r.WithContext(ctx)
	}
	if pathOK {
		if !methodOK {
			w.Header().Set(headerAllow, allowedMethods(s.routes, r.URL.Path))
			s.writeProblem(w, r, instance, domainerr.MethodNotAllowed("method not allowed"))
			return
		}
		if !s.skipAuth(r.Context(), rt.cap) {
			if err := s.rate.allow(r.RemoteAddr); err != nil {
				s.writeProblem(w, r, instance, err)
				return
			}
		}
		skip := s.skipAuth(r.Context(), rt.cap)
		actor, err := s.authenticate(r, skip)
		if err != nil {
			s.writeProblem(w, r, instance, err)
			return
		}
		if !skip {
			if err := s.authorize(r, actor, rt.cap); err != nil {
				s.writeProblem(w, r, instance, err)
				return
			}
		}
		s.dispatch(w, r, instance, actor, rt, params)
		return
	}

	if s.tryUI(w, r, instance) {
		return
	}
	s.writeProblem(w, r, instance, domainerr.NotFound("not found"))
}

func isHealthCap(cap capabilities.Capability) bool {
	return cap.ID == capabilities.HealthLive || cap.ID == capabilities.HealthReady
}

func (s *Server) skipAuth(ctx context.Context, cap capabilities.Capability) bool {
	if isHealthCap(cap) {
		return true
	}
	return cap.ID == capabilities.MetricsGet && s.publicMetrics(ctx)
}

func (s *Server) allowedOrigins() []string {
	s.sec.RLock()
	defer s.sec.RUnlock()
	return append([]string(nil), s.cfg.AllowedOrigins...)
}

func (s *Server) publicMetrics(ctx context.Context) bool {
	if s.svc != nil {
		if ctx == nil {
			ctx = context.Background()
		}
		st, err := s.svc.GetState(ctx, app.Actor{ID: "probe", Class: "startup", Transport: "rest"})
		if err == nil && st != nil && st.Canonical != nil {
			return st.Canonical.Spec.Observability.Metrics.PublicPath
		}
	}
	s.sec.RLock()
	defer s.sec.RUnlock()
	return s.cfg.PublicMetrics
}

func (s *Server) reloadAuth() {
	appSvc, ok := s.svc.(*app.App)
	if !ok {
		return
	}
	snap := appSvc.Active()
	if snap == nil || snap.Canonical == nil {
		return
	}
	s.sec.Lock()
	s.cfg.AllowedOrigins = append([]string(nil), snap.Canonical.Spec.Management.AllowedOrigins...)
	s.cfg.PublicMetrics = snap.Canonical.Spec.Observability.Metrics.PublicPath
	s.sec.Unlock()

	if s.cfg.Auth == nil {
		return
	}
	next, err := auth.FromSpecAt(snap.Canonical.Spec.Auth, appSvc.BootstrapDir())
	if err != nil {
		next = auth.Empty()
	}
	changed := !s.cfg.Auth.Equivalent(next)
	s.cfg.Auth.Replace(next)
	if changed && s.cfg.Sessions != nil {
		s.cfg.Sessions.Clear()
	}
}

func (s *Server) dispatchMount(w http.ResponseWriter, r *http.Request, instance string) bool {
	if s.mounts == nil {
		return false
	}
	h, pattern := s.mounts.Handler(r)
	if pattern == "" {
		return false
	}
	if err := s.rate.allow(r.RemoteAddr); err != nil {
		s.writeProblem(w, r, instance, err)
		return true
	}
	if _, err := s.authenticateBearer(r); err != nil {
		s.writeProblem(w, r, instance, err)
		return true
	}
	h.ServeHTTP(w, r)
	return true
}

func (s *Server) isLive() bool {
	if s.cfg.Live != nil {
		return s.cfg.Live()
	}
	return true
}

func (s *Server) isReady(ctx context.Context) bool {
	if s.cfg.Ready != nil {
		return s.cfg.Ready()
	}
	st, err := s.svc.Status(ctx, app.Actor{ID: "probe", Class: "startup", Transport: "rest"})
	if err != nil {
		return false
	}
	return st.Ready
}

func (s *Server) observeHTTP(route string, status int, start time.Time, reqID string) {
	if s.metrics != nil {
		s.metrics.Inc(observability.MetricHTTPRequestsTotal, map[string]string{
			"code":  observability.HTTPCode(status),
			"route": observability.HTTPRoute(route),
		}, 1)
	}
	if s.logger != nil {
		s.logger.Log(observability.Record{
			Event:      observability.EventHTTPRequest,
			Component:  "rest",
			RequestID:  reqID,
			Capability: route,
			Result:     observability.HTTPCode(status),
			DurationMS: float64(time.Since(start).Milliseconds()),
		})
	}
}

func requestID(r *http.Request) string {
	if id := r.Header.Get(headerRequestID); id != "" {
		return id
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-fallback"
	}
	return hex.EncodeToString(b[:])
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(status int) {
	w.code = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) status() int {
	if w.code == 0 {
		return http.StatusOK
	}
	return w.code
}
