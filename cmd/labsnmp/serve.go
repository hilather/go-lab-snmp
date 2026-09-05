package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/auth"
	"github.com/hilather/go-lab-snmp/internal/buildinfo"
	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/control/mcp"
	"github.com/hilather/go-lab-snmp/internal/control/rest"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/observability"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
	"github.com/hilather/go-lab-snmp/internal/snmpagent"
	"github.com/hilather/go-lab-snmp/internal/snmpsink"
	"github.com/hilather/go-lab-snmp/internal/store"
	"github.com/hilather/go-lab-snmp/internal/web"
)

const defaultShutdownTimeout = 10 * time.Second

type serveFlags struct {
	Config           string
	SNMPListen       string
	TrapListen       string
	ManagementListen string
	ShutdownTimeout  time.Duration
	PIDFile          string
}

func parseServeFlags(args []string, stderr io.Writer) (serveFlags, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "path to bootstrap YAML or JSON")
	snmpListen := fs.String("snmp-listen", "", "override agent listen address (empty uses YAML)")
	trapListen := fs.String("trap-listen", "", "override trap listen address (empty uses YAML; off disables)")
	mgmtListen := fs.String("management-listen", "off", "management listen; off/none/- leaves it unbound")
	shutdown := fs.Duration("shutdown-timeout", defaultShutdownTimeout, "graceful shutdown deadline")
	pidFile := fs.String("pid-file", "", "write process id after listeners bind")
	if err := fs.Parse(args); err != nil {
		return serveFlags{}, err
	}
	if *path == "" {
		_, _ = fmt.Fprintln(stderr, "labsnmp serve: --config is required")
		return serveFlags{}, fmt.Errorf("missing --config")
	}
	return serveFlags{
		Config:           *path,
		SNMPListen:       *snmpListen,
		TrapListen:       *trapListen,
		ManagementListen: *mgmtListen,
		ShutdownTimeout:  *shutdown,
		PIDFile:          *pidFile,
	}, nil
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

func resolveTrapListen(flag string, st *model.State) (addr string, enabled bool) {
	yamlAddr, on := "", false
	if st != nil {
		yamlAddr, on = st.Spec.Listeners.Traps.Address, st.Spec.Listeners.Traps.Enabled
		if yamlAddr == "" && on {
			yamlAddr = config.DefaultTrapAddress
		}
	}
	addr = resolveUDP(flag, yamlAddr, on)
	return addr, addr != ""
}

func resolveUDP(flag, yamlAddr string, enabled bool) string {
	switch {
	case listenOff(flag):
		return ""
	case listenAddress(flag):
		return strings.TrimSpace(flag)
	case !enabled:
		return ""
	default:
		return yamlAddr
	}
}

func desiredUDP(flags serveFlags, snap *snapshot.Snapshot) app.DesiredListeners {
	var agentAddr, trapAddr string
	agentOn, trapOn := false, false
	if snap != nil {
		agentAddr, agentOn = snap.AgentAddress, snap.AgentEnabled
		trapAddr, trapOn = snap.TrapAddress, snap.TrapsEnabled
	}
	return app.DesiredListeners{
		AgentUDP: resolveUDP(flags.SNMPListen, agentAddr, agentOn),
		TrapUDP:  resolveUDP(flags.TrapListen, trapAddr, trapOn),
	}
}

func serveCmd(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveWithContext(ctx, args, stdout, stderr)
}

func serveWithContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags, err := parseServeFlags(args, stderr)
	if err != nil {
		return 2
	}
	metrics := observability.NewRegistry()
	info := buildinfo.Current()
	metrics.Set(observability.MetricBuildInfo, map[string]string{
		"version": info.Version,
		"commit":  info.Commit,
	}, 1)
	logger := observability.NewLogger(stderr, observability.LevelInfo)
	logger.SetRegistry(metrics)
	svc, err := app.Boot(ctx, app.Options{
		BootstrapPath:      flags.Config,
		SNMPListenOverride: flags.SNMPListen,
		TrapListenOverride: flags.TrapListen,
		MgmtListenOverride: flags.ManagementListen,
		Metrics:            metrics,
		Logger:             logger,
	})
	if err != nil {
		printDomainError(stderr, "labsnmp serve", err)
		return 1
	}
	snap := svc.Active()
	if snap == nil || snap.Canonical == nil {
		_, _ = fmt.Fprintln(stderr, "labsnmp serve: compile produced no snapshot")
		return 1
	}
	for _, w := range snap.Warnings {
		_, _ = fmt.Fprintf(stderr, "warning %s: %s\n", w.Path, w.Message)
	}
	st := snap.Canonical
	if st != nil {
		logger = observability.NewLogger(stderr, observability.ParseLevel(st.Spec.Observability.LogLevel))
		logger.SetRegistry(metrics)
		svc.SetLogger(logger)
	}

	desired := desiredUDP(flags, snap)
	if desired.AgentUDP == "" {
		_, _ = fmt.Fprintln(stderr, "labsnmp serve: agent listener is disabled")
		return 1
	}

	srv, err := snmpagent.New(snmpagent.Config{
		Addr:    desired.AgentUDP,
		Store:   svc.Snapshots(),
		Overlay: svc.Overlay(),
		Queries: svc.Queries(),
		Clock:   snap.Clock,
		Metrics: metrics,
		Logger:  logger,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "labsnmp serve: %v\n", err)
		return 1
	}

	sink, err := newTrapSink(desired.TrapUDP, svc.Snapshots(), snap, svc.Traps(), metrics, logger)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "labsnmp serve: %v\n", err)
		shctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = srv.Shutdown(shctx)
		cancel()
		return 1
	}
	dp := &dataPlane{agent: srv, sink: sink}
	if err := dp.Sync(desired); err != nil {
		_, _ = fmt.Fprintf(stderr, "labsnmp serve: %v\n", err)
		shctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = sink.Shutdown(shctx)
		_ = srv.Shutdown(shctx)
		cancel()
		return 1
	}
	svc.SetDataPlaneSync(dp.Sync)
	_, _ = fmt.Fprintf(stdout, "labsnmp snmp listen=%s\n", srv.Addr().String())
	if sink.Bound() {
		_, _ = fmt.Fprintf(stdout, "labsnmp trap listen=%s\n", sink.Addr().String())
	} else {
		_, _ = fmt.Fprintln(stdout, "labsnmp trap: not bound")
	}

	var restSrv *rest.Server
	var mcpSrv *mcp.Server
	mgmtOff := !listenAddress(flags.ManagementListen)
	svc.SetHealth(func() observability.Facts {
		want := dp.last()
		return observability.Facts{
			AgentBound: srv.Bound(),
			AgentOff:   want.AgentUDP == "",
			TrapBound:  sink != nil && sink.Bound(),
			TrapOff:    want.TrapUDP == "",
			MgmtBound:  restSrv != nil && restSrv.Bound(),
			MgmtOff:    mgmtOff,
		}
	})
	syncObs := func() {
		live := svc.Active()
		if live == nil || live.Canonical == nil {
			return
		}
		logger.SetLevel(observability.ParseLevel(live.Canonical.Spec.Observability.LogLevel))
	}
	svc.OnApply(syncObs)
	svc.OnReset(syncObs)
	if !mgmtOff {
		v, vErr := auth.FromSpecAt(st.Spec.Auth, filepath.Dir(flags.Config))
		if vErr != nil {
			_, _ = fmt.Fprintf(stderr, "labsnmp serve: auth: %v\n", vErr)
			shctx, cancel := context.WithTimeout(context.Background(), time.Second)
			if sink != nil {
				_ = sink.Shutdown(shctx)
			}
			_ = srv.Shutdown(shctx)
			cancel()
			return 1
		}
		if err := v.RequireListen(); err != nil {
			_, _ = fmt.Fprintf(stderr, "labsnmp serve: %v\n", err)
			shctx, cancel := context.WithTimeout(context.Background(), time.Second)
			if sink != nil {
				_ = sink.Shutdown(shctx)
			}
			_ = srv.Shutdown(shctx)
			cancel()
			return 1
		}
		origins := []string{}
		bodyLimit := config.DefaultBodyLimit
		publicMetrics := false
		allowLegacy := false
		if st != nil {
			origins = st.Spec.Management.AllowedOrigins
			if st.Spec.Management.BodyLimit > 0 {
				bodyLimit = st.Spec.Management.BodyLimit
			}
			publicMetrics = st.Spec.Observability.Metrics.PublicPath
			allowLegacy = st.Spec.Management.MCP.AllowLegacyClients
		}
		mcpSrv, err = mcp.New(mcp.Config{
			Service:            svc,
			AllowedOrigins:     origins,
			AllowLegacyClients: allowLegacy,
			RatePerSec:         -1,
			MaxBodyBytes:       bodyLimit,
			Auth:               v,
		})
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "labsnmp serve: mcp: %v\n", err)
			shctx, cancel := context.WithTimeout(context.Background(), time.Second)
			if sink != nil {
				_ = sink.Shutdown(shctx)
			}
			_ = srv.Shutdown(shctx)
			cancel()
			return 1
		}
		mcpPath := mcp.DefaultPath
		if st != nil && strings.TrimSpace(st.Spec.Listeners.Management.MCPPath) != "" {
			mcpPath = st.Spec.Listeners.Management.MCPPath
		}
		restSrv, err = rest.New(rest.Config{
			Addr:           flags.ManagementListen,
			Service:        svc,
			AllowedOrigins: origins,
			MaxBodyBytes:   bodyLimit,
			RatePerSec:     0,
			PublicMetrics:  publicMetrics,
			Auth:           v,
			Live:           func() bool { return true },
			Ready: func() bool {
				return observability.Evaluate(svc.HealthFacts()).Ready
			},
			Metrics:   metrics,
			Logger:    logger,
			UI:        web.NewHandler(nil),
			UIEnabled: serveUIEnabled(svc),
			Mounts: map[string]http.Handler{
				mcpPath: mcpSrv.Handler(),
			},
		})
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "labsnmp serve: rest: %v\n", err)
			mcpSrv.Close()
			shctx, cancel := context.WithTimeout(context.Background(), time.Second)
			if sink != nil {
				_ = sink.Shutdown(shctx)
			}
			_ = srv.Shutdown(shctx)
			cancel()
			return 1
		}
		svc.SetHTTPRebind(restSrv.Rebind)
		go func() {
			if err := restSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				_, _ = fmt.Fprintf(stderr, "labsnmp management: %v\n", err)
			}
		}()
		deadline := time.Now().Add(2 * time.Second)
		for !restSrv.Bound() && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		_, _ = fmt.Fprintf(stdout, "labsnmp management listen=%s\n", restSrv.Addr())
	} else {
		_, _ = fmt.Fprintln(stdout, "labsnmp management: not bound")
	}

	pidWritten := false
	if flags.PIDFile != "" {
		if err := os.WriteFile(flags.PIDFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
			_, _ = fmt.Fprintf(stderr, "labsnmp serve: pid-file: %v\n", err)
			shutdownPlanes(restSrv, sink, srv, flags.ShutdownTimeout)
			return 1
		}
		pidWritten = true
	}

	<-ctx.Done()
	shutdownPlanes(restSrv, sink, srv, flags.ShutdownTimeout)
	if pidWritten {
		_ = os.Remove(flags.PIDFile)
	}
	if mcpSrv != nil {
		mcpSrv.Close()
	}
	_, _ = fmt.Fprintln(stdout, "labsnmp: shutting down")
	return 0
}

func shutdownPlanes(restSrv *rest.Server, sink *snmpsink.Server, srv *snmpagent.Server, d time.Duration) {
	if d <= 0 {
		d = defaultShutdownTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	if restSrv != nil {
		_ = restSrv.Shutdown(ctx)
	}
	if sink != nil {
		_ = sink.Shutdown(ctx)
	}
	if srv != nil {
		_ = srv.Shutdown(ctx)
	}
}

func serveUIEnabled(svc *app.App) func() bool {
	return func() bool {
		if !web.UIEnabled {
			return false
		}
		if svc == nil {
			return false
		}
		live := svc.Active()
		if live == nil || live.Canonical == nil {
			return false
		}
		return live.Canonical.Spec.UI.Enabled
	}
}

func newTrapSink(addr string, snaps *snapshot.Store, snap *snapshot.Snapshot, ring *store.TrapRing, metrics *observability.Registry, logger *observability.Logger) (*snmpsink.Server, error) {
	if ring == nil {
		ring = store.NewTrapRing(store.TrapPolicy{
			MaxMessages: snap.Canonical.Spec.Traps.MaxMessages,
			MaxBytes:    snap.Canonical.Spec.Traps.MaxBytes,
			FullPolicy:  snap.Canonical.Spec.Traps.FullPolicy,
			MaxWait:     snap.Canonical.Spec.Traps.MaxWait,
		})
	}
	comms := make(map[string]*snmpsink.Community, len(snap.Communities))
	for k, c := range snap.Communities {
		vers := make(map[string]bool, len(c.Versions))
		for vk, vv := range c.Versions {
			vers[vk] = vv
		}
		comms[k] = &snmpsink.Community{
			Name:     c.Name,
			Wire:     append([]byte(nil), c.Wire...),
			Versions: vers,
		}
	}
	agentVers := make(map[string]bool, len(snap.Versions))
	for vk, vv := range snap.Versions {
		agentVers[vk] = vv
	}
	return snmpsink.New(snmpsink.Config{
		Addr:                  addr,
		Store:                 ring,
		Snapshots:             snaps,
		Communities:           comms,
		Engine:                snap.Engine,
		Versions:              agentVers,
		AcceptUnauthenticated: snap.AcceptUnauthenticated,
		RawRetain:             snap.RawRetain,
		MaxMessageBytes:       snap.MaxMessageBytes,
		Allow:                 snap.Allow,
		MaxPerSec:             snap.MaxPerSec,
		MaxPerIP:              snap.MaxPerIP,
		Clock:                 sinkClock{snap.Clock},
		Metrics:               metrics,
		Logger:                logger,
	})
}

type sinkClock struct{ snapshot.Clock }

func (c sinkClock) Now() time.Time {
	if c.Clock == nil {
		return time.Now()
	}
	return c.Clock.Now()
}
