package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/app"
	"github.com/hilather/go-lab-snmp/internal/auth"
	"github.com/hilather/go-lab-snmp/internal/model"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const testBearerToken = "abcdefghijklmnopqrstuvwxyz123456"

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func bootTestApp(t *testing.T) *app.App {
	t.Helper()
	t.Chdir(repoRoot(t))
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "testdata", "config", "valid", "full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "labsnmp.yaml")
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}
	svc, err := app.Boot(context.Background(), app.Options{BootstrapPath: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	return svc
}

func newTestServer(t *testing.T) (*Server, *app.App) {
	t.Helper()
	svc := bootTestApp(t)
	s, err := New(Config{
		Service:            svc,
		RatePerSec:         -1,
		AllowLegacyClients: true,
		Auth:               auth.Static(testBearerToken, "admin", model.RoleAdministrator),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, svc
}

func newPinnedServer(t *testing.T) (*Server, *app.App) {
	t.Helper()
	svc := bootTestApp(t)
	s, err := New(Config{
		Service:            svc,
		RatePerSec:         -1,
		AllowLegacyClients: false,
		Auth:               auth.Static(testBearerToken, "admin", model.RoleAdministrator),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, svc
}

type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (b bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set(headerAuthorization, "Bearer "+b.token)
	base := b.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}

func startHTTP(t *testing.T, s *Server) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func connectClient(t *testing.T, ts *httptest.Server) *sdk.ClientSession {
	t.Helper()
	return connectClientAuth(t, ts, testBearerToken)
}

func connectClientAuth(t *testing.T, ts *httptest.Server, token string) *sdk.ClientSession {
	t.Helper()
	client := sdk.NewClient(&sdk.Implementation{Name: "labsnmp-test", Version: "dev"}, nil)
	session, err := client.Connect(t.Context(), &sdk.StreamableClientTransport{
		Endpoint:             ts.URL,
		DisableStandaloneSSE: true,
		HTTPClient:           &http.Client{Transport: bearerRoundTripper{token: token}},
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func rpcCall(id int, method string, params any) string {
	p := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		p["params"] = params
	} else {
		p["params"] = map[string]any{
			"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": ProtocolVersion},
		}
	}
	b, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func doRaw(t *testing.T, h http.Handler, body string, hdr map[string]string, remote string) *httptest.ResponseRecorder {
	t.Helper()
	return doRawMethod(t, h, http.MethodPost, "/", body, hdr, remote)
}

func doRawMethod(t *testing.T, h http.Handler, method, path, body string, hdr map[string]string, remote string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remote
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeRPC(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	raw := rec.Body.Bytes()
	if bytes.Contains(raw, []byte("event:")) {
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "data:") {
				raw = []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json: %v body=%s", err, rec.Body.String())
	}
	return out
}

func requireRPCError(t *testing.T, rec *httptest.ResponseRecorder, status int, domainCode string) map[string]any {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status=%d want %d body=%s", rec.Code, status, rec.Body.String())
	}
	m := decodeRPC(t, rec)
	errObj, _ := m["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("missing error: %s", rec.Body.String())
	}
	data, _ := errObj["data"].(map[string]any)
	if data == nil {
		t.Fatalf("missing error.data: %s", rec.Body.String())
	}
	if got, _ := data["code"].(string); got != domainCode {
		t.Fatalf("data.code=%v want %s body=%s", data["code"], domainCode, rec.Body.String())
	}
	return errObj
}

func callTool(t *testing.T, cs *sdk.ClientSession, name string, args any) *sdk.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	return res
}

func structuredMap(t *testing.T, res *sdk.CallToolResult) map[string]any {
	t.Helper()
	if res.IsError {
		var texts []string
		for _, c := range res.Content {
			if tc, ok := c.(*sdk.TextContent); ok {
				texts = append(texts, tc.Text)
			}
		}
		t.Fatalf("tool error structured=%v text=%v", res.StructuredContent, texts)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("structured: %v raw=%s", err, raw)
	}
	return out
}
