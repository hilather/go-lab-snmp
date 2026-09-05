package snmpagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultMaxInflight  = 1024
	DefaultShutdownWait = 5 * time.Second
)

// Config is the UDP/161 listener configuration.
type Config struct {
	Addr        string
	Runtime     *Runtime
	MaxInflight int
}

// Server is a unicast SNMPv1/v2c/v3 UDP listener.
type Server struct {
	cfg Config
	rt  *Runtime

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	udp      net.PacketConn
	bindAddr string
	started  bool
	stopped  bool

	inflight chan struct{}
	global   *queryLimiter
	perIP    *queryLimiter

	wg sync.WaitGroup

	AuthFail  atomic.Int64
	Allowlist atomic.Int64
	Admission atomic.Int64
	Dropped   atomic.Int64
	Served    atomic.Int64
}

// New validates cfg. Start binds and serves.
func New(cfg Config) (*Server, error) {
	if cfg.Runtime == nil {
		return nil, errors.New("snmpagent: Runtime is required")
	}
	if cfg.Addr == "" {
		return nil, errors.New("snmpagent: Addr is required")
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = DefaultMaxInflight
	}
	now := time.Now
	if cfg.Runtime.Clock != nil {
		clk := cfg.Runtime.Clock
		now = clk.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:      cfg,
		rt:       cfg.Runtime,
		ctx:      ctx,
		cancel:   cancel,
		bindAddr: cfg.Addr,
		inflight: make(chan struct{}, cfg.MaxInflight),
		global:   newQueryLimiter(float64(cfg.Runtime.MaxPerSec), float64(cfg.Runtime.MaxPerSec), now),
		perIP:    newQueryLimiter(float64(cfg.Runtime.MaxPerIP), float64(cfg.Runtime.MaxPerIP), now),
	}, nil
}

// Start binds ListenPacket("udp") and serves in the background.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("snmpagent: already started")
	}
	if s.stopped {
		return errors.New("snmpagent: start after shutdown")
	}
	pc, err := net.ListenPacket("udp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("snmpagent: udp listen: %w", err)
	}
	s.udp = pc
	s.bindAddr = s.cfg.Addr
	s.started = true
	s.wg.Add(1)
	go s.serveUDP()
	return nil
}

// Bound reports whether a PacketConn is currently serving.
func (s *Server) Bound() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udp != nil && s.started && !s.stopped
}

// Ready is AGENT-001: Runtime loaded, agent bound, management off (caller).
func (s *Server) Ready() bool {
	return s != nil && s.rt != nil && s.Bound()
}

// Addr is the bound UDP address, or nil.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udp == nil {
		return nil
	}
	return s.udp.LocalAddr()
}

// Shutdown stops the read loop and waits up to ctx.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	s.cancel()
	udp := s.udp
	s.mu.Unlock()
	if udp != nil {
		_ = udp.Close()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) conn() net.PacketConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udp
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	max := int(s.rt.MaxMessageBytes)
	if max < 1 {
		max = 64 << 10
	}
	buf := make([]byte, max+1)
	for {
		if s.ctx.Err() != nil {
			return
		}
		pc := s.conn()
		if pc == nil {
			return
		}
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if s.ctx.Err() != nil || isClosed(err) {
				return
			}
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case s.inflight <- struct{}{}:
		default:
			s.Admission.Add(1)
			s.Dropped.Add(1)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.inflight }()
			s.handle(pkt, addr)
		}()
	}
}

func isClosed(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	return errors.Is(err, context.Canceled)
}
