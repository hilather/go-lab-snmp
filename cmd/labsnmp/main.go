// Command labsnmp is the LabSNMP process entrypoint.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/hilather/go-lab-snmp/internal/buildinfo"
)

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		printUsage(stderr)
		return 2
	}
	switch args[1] {
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	case "version", "-v", "--version":
		_, _ = fmt.Fprintln(stdout, buildinfo.Current().String())
		return 0
	case "validate":
		return validateCmd(args[2:], stdout, stderr)
	case "canonicalize":
		return canonicalizeCmd(args[2:], stdout, stderr)
	case "serve":
		return serveCmd(args[2:], stdout, stderr)
	case "healthcheck":
		return healthcheckCmd(args[2:], stdout, stderr)
	case "mcp-stdio":
		_, _ = fmt.Fprintf(stderr, "labsnmp %s: not implemented\n", args[1])
		return 1
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n", args[1])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	_, _ = io.WriteString(w, usageText)
}

const usageText = `usage: labsnmp <command>

LabSNMP is a laboratory SNMPv1/v2c/v3 agent with a receive-only
trap/inform sink. validate and canonicalize load a fail-closed
labsnmp.dev/v1alpha1 document. serve binds the agent and trap UDP
sockets. --trap-listen empty uses YAML traps.address; off disables.
--management-listen defaults off. YAML management.address does not
bind unless this flag is an address. spec.ui.enabled false keeps
GET / as 404 problem+json. /v1 requires bearer or labsnmp_session
except health live/ready (and metrics if publicPath).

Commands:
  version         print build and protocol metadata
  help            print this help
  validate        fail-closed YAML check (--config)
  canonicalize    emit canonical spec (--config, --format yaml|json)
  serve           bind SNMP (--config, --snmp-listen, --trap-listen,
                  --management-listen, --shutdown-timeout, --pid-file)
  healthcheck     probe GET /v1/health/ready (--url)
  mcp-stdio       Streamable MCP over stdio (--config, --token-file)
`
