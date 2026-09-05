package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/snmpagent"
)

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
	trapListen := fs.String("trap-listen", "off", "trap listen; off until TRAP-001 (address rejected)")
	mgmtListen := fs.String("management-listen", "off", "management listen; off until DEP-001 (address rejected)")
	shutdown := fs.Duration("shutdown-timeout", snmpagent.DefaultShutdownWait, "graceful shutdown deadline")
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
	if listenAddress(flags.TrapListen) {
		_, _ = fmt.Fprintln(stderr, "labsnmp serve: --trap-listen is not implemented until TRAP-001")
		return 2
	}
	if listenAddress(flags.ManagementListen) {
		_, _ = fmt.Fprintln(stderr, "labsnmp serve: --management-listen is not implemented until DEP-001")
		return 2
	}

	st, warns, err := config.LoadFileWithWarnings(flags.Config)
	if err != nil {
		printDomainError(stderr, "labsnmp serve", err)
		return 1
	}
	for _, w := range warns {
		_, _ = fmt.Fprintf(stderr, "warning %s: %s\n", w.Path, w.Message)
	}

	rt, err := snmpagent.Load(st, snmpagent.LoadOptions{BaseDir: filepath.Dir(flags.Config)})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "labsnmp serve: %v\n", err)
		return 1
	}

	addr := strings.TrimSpace(flags.SNMPListen)
	switch {
	case listenOff(addr):
		_, _ = fmt.Fprintln(stderr, "labsnmp serve: agent listener is disabled")
		return 1
	case addr == "":
		if !st.Spec.Listeners.Agent.Enabled {
			_, _ = fmt.Fprintln(stderr, "labsnmp serve: agent listener is disabled")
			return 1
		}
		addr = st.Spec.Listeners.Agent.Address
		if addr == "" {
			addr = config.DefaultAgentAddress
		}
	}

	srv, err := snmpagent.New(snmpagent.Config{Addr: addr, Runtime: rt})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "labsnmp serve: %v\n", err)
		return 1
	}
	if err := srv.Start(); err != nil {
		_, _ = fmt.Fprintf(stderr, "labsnmp serve: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "labsnmp snmp listen=%s\n", srv.Addr().String())

	// Trap stays off until TRAP-001 even if YAML traps.enabled is true.
	_, _ = fmt.Fprintln(stdout, "labsnmp trap: not bound")

	_, _ = fmt.Fprintln(stdout, "labsnmp management: not bound")

	if flags.PIDFile != "" {
		if err := os.WriteFile(flags.PIDFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
			_, _ = fmt.Fprintf(stderr, "labsnmp serve: pid-file: %v\n", err)
		}
	}

	<-ctx.Done()
	deadline := flags.ShutdownTimeout
	if deadline <= 0 {
		deadline = snmpagent.DefaultShutdownWait
	}
	shctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	_ = srv.Shutdown(shctx)
	_, _ = fmt.Fprintln(stdout, "labsnmp: shutting down")
	return 0
}
