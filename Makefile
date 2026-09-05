# LabSNMP task runner. Tool versions are pinned; do not use @latest.

GO ?= go
export GOPROXY ?= https://proxy.golang.org,direct

GOLANGCI_LINT_VERSION ?= v2.12.2
GOVULNCHECK_MOD ?= golang.org/x/vuln/cmd/govulncheck@v1.1.4
GOLANGCI_LINT_MOD ?= github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: help fmt format lint vet build generate verify-generated test test-race \
	test-fuzz-smoke test-parity test-config-compat test-docs test-container \
	security-scan test-changelog web-install web-test web-build web-embed

help:
	@printf '%s\n' \
		'LabSNMP Make targets (Go 1.26; module github.com/hilather/go-lab-snmp)' \
		'  format              go fmt ./...' \
		'  fmt                 alias for format' \
		'  vet                 go vet ./...' \
		'  lint                go vet + golangci-lint $(GOLANGCI_LINT_VERSION)' \
		'  build               go build -o bin/labsnmp ./cmd/labsnmp' \
		'  generate            write api/capabilities, openapi, mcp, metrics JSON' \
		'  verify-generated    fail if generate would change those files' \
		'  test                go test ./...' \
		'  test-race           go test -race ./...' \
		'  test-fuzz-smoke     buildinfo + config + snmpwire fuzz corpora' \
		'  test-docs           required documents, metadata, links, and required phrases' \
		'  security-scan       govulncheck' \
		'  test-parity         REST/MCP capability parity goldens' \
		'  test-config-compat  positive+negative v1alpha1 config fixtures' \
		'  web-install         npm ci in web/' \
		'  web-test            Vitest operator SPA tests' \
		'  web-build           production Vite build + copy into internal/web/dist' \
		'  web-embed           copy web/dist into internal/web/dist' \
		'  test-container      build image and check non-root/read-only/no-caps' \
		'  test-changelog      observable paths require a CHANGELOG.md entry'

fmt: format

format:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

lint: vet
	$(GO) run $(GOLANGCI_LINT_MOD) run ./...

build:
	$(GO) build -o bin/labsnmp ./cmd/labsnmp

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

test-docs:
	$(GO) run ./scripts/checkdocs

test-changelog:
	$(GO) run ./scripts/checkchangelog

test-config-compat:
	$(GO) test ./internal/config -run TestConfigCompat -count=1

test-fuzz-smoke:
	$(GO) test ./scripts/checkdocs -run TestFuzzCorporaPresent -count=1
	$(GO) test ./internal/buildinfo -fuzz=FuzzInfoString -fuzztime=5s -count=1
	$(GO) test ./internal/config -fuzz=FuzzDecode -fuzztime=5s -count=1
	$(GO) test ./internal/snmpwire -fuzz=FuzzDecode -fuzztime=10s -count=1
	$(GO) test ./internal/snmpwire -fuzz=FuzzParseOID -fuzztime=5s -count=1

generate:
	$(GO) run ./scripts/generate

verify-generated:
	$(GO) run ./scripts/generate -check

test-parity \
test-container security-scan:
	@echo 'make $@: not implemented' >&2
	@false

web-install:
	npm --prefix web ci

web-test:
	npm --prefix web test

web-build:
	npm --prefix web run build
	$(MAKE) web-embed

web-embed:
	@mkdir -p internal/web/dist
	@rm -rf internal/web/dist/assets
	@if [ -d web/dist ]; then cp -a web/dist/. internal/web/dist/; fi
	@echo "copied web/dist -> internal/web/dist"
