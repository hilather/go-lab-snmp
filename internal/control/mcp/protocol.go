package mcp

import (
	"context"
	"net/http"
	"strings"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func validateProtocolVersion(r *http.Request) error {
	ver := strings.TrimSpace(r.Header.Get(headerProtocolVersion))
	if ver == "" {
		return domainerr.ValidationFailed("MCP-Protocol-Version is required; only "+ProtocolVersion+" is supported",
			domainerr.FieldViolation{Path: "MCP-Protocol-Version", Code: "required", Message: "only " + ProtocolVersion + " is supported"})
	}
	if ver != ProtocolVersion {
		return domainerr.ValidationFailed("unsupported MCP protocol version "+ver+"; only "+ProtocolVersion+" is supported",
			domainerr.FieldViolation{Path: "MCP-Protocol-Version", Code: "invalid_value", Message: "only " + ProtocolVersion + " is supported"})
	}
	return nil
}

func (s *Server) pinProtocolMiddleware(next sdk.MethodHandler) sdk.MethodHandler {
	return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
		if !s.allowLegacy() {
			if v := requestProtocolVersion(req); v != "" && v != ProtocolVersion {
				return nil, rpcError(domainerr.ValidationFailed("unsupported MCP protocol version "+v+"; only "+ProtocolVersion+" is supported",
					domainerr.FieldViolation{Path: "protocolVersion", Code: "invalid_value", Message: "only " + ProtocolVersion + " is supported"}))
			}
		}
		res, err := next(ctx, method, req)
		if err != nil {
			return nil, err
		}
		if dr, ok := res.(*sdk.DiscoverResult); ok && dr != nil {
			dr.SupportedVersions = []string{ProtocolVersion}
		}
		return res, nil
	}
}

func requestProtocolVersion(req sdk.Request) string {
	if sr, ok := req.(interface{ ProtocolVersion() string }); ok {
		if v := sr.ProtocolVersion(); v != "" {
			return v
		}
	}
	if gp, ok := req.(interface{ GetParams() sdk.Params }); ok {
		if p, ok := gp.GetParams().(*sdk.InitializeParams); ok && p != nil {
			return p.ProtocolVersion
		}
	}
	return ""
}
