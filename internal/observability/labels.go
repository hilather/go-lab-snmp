package observability

import (
	"strconv"
	"strings"
)

var (
	forbiddenSet = indexStrings(ForbiddenLabels)
	allowedSet   = indexStrings(AllowedLabels)
)

func indexStrings(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		out[strings.ToLower(s)] = struct{}{}
	}
	return out
}

// ForbiddenLabel reports whether key is a prohibited default label.
func ForbiddenLabel(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		return false
	}
	if _, ok := forbiddenSet[k]; ok {
		return true
	}
	if strings.Contains(k, "client_ip") || strings.Contains(k, "remote_addr") ||
		strings.Contains(k, "password") || strings.Contains(k, "cookie") ||
		strings.Contains(k, "community") || strings.Contains(k, "secret") ||
		strings.Contains(k, "token") || strings.Contains(k, "passphrase") {
		return true
	}
	return false
}

// AllowedLabel reports whether key is in the global allowlist.
func AllowedLabel(key string) bool {
	_, ok := allowedSet[strings.ToLower(strings.TrimSpace(key))]
	return ok
}

func checkLabelsDef(def MetricDef, labels map[string]string) error {
	allowed := make(map[string]struct{}, len(def.Labels))
	for _, l := range def.Labels {
		allowed[l] = struct{}{}
	}
	for k := range labels {
		if ForbiddenLabel(k) {
			return labelError("forbidden_label")
		}
		if _, ok := allowed[k]; !ok {
			return labelError("unknown_label")
		}
	}
	return nil
}

type labelError string

func (e labelError) Error() string { return string(e) }

// LabelReason is the bounded drop reason for a rejected sample.
func LabelReason(err error) string {
	if err == nil {
		return ""
	}
	if r, ok := err.(labelError); ok {
		return string(r)
	}
	return "invalid"
}

// SNMPVersion collapses a version string to a catalog label.
func SNMPVersion(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "v1", "1":
		return "v1"
	case "v2c", "v2", "2", "2c":
		return "v2c"
	case "v3", "3":
		return "v3"
	default:
		return "unknown"
	}
}

// PDUType collapses a PDU name to a catalog label.
func PDUType(p string) string {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "-", "")) {
	case "get":
		return "get"
	case "getnext":
		return "getnext"
	case "getbulk":
		return "getbulk"
	case "set":
		return "set"
	case "trap", "trapv1":
		return "trapv1"
	case "trapv2", "snmpv2trap":
		return "trapv2"
	case "inform":
		return "inform"
	case "report":
		return "report"
	case "response":
		return "response"
	default:
		return "unknown"
	}
}

// PDUDecision collapses an agent packet-path outcome to a catalog decision label.
func PDUDecision(d string) string {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "ok", "serve":
		return "ok"
	case "drop", "auth_fail", "allowlist", "admission", "version",
		"oversize", "decode", "unmatched":
		return strings.ToLower(strings.TrimSpace(d))
	default:
		return "drop"
	}
}

// TrapDecision collapses a trap-path outcome to a catalog decision label.
func TrapDecision(d string) string {
	switch strings.ToLower(strings.TrimSpace(d)) {
	case "ok", "stored", "serve":
		return "ok"
	case "drop", "auth_fail", "allowlist", "admission", "version",
		"oversize", "decode", "unmatched":
		return strings.ToLower(strings.TrimSpace(d))
	default:
		return "drop"
	}
}

// HTTPCode is the bounded numeric status label for labsnmp_http_requests_total.
func HTTPCode(status int) string {
	if status < 100 || status > 599 {
		return "000"
	}
	return strconv.Itoa(status)
}

// HTTPRoute collapses an unmatched path to "other". Known routes pass through.
func HTTPRoute(route string) string {
	r := strings.TrimSpace(route)
	if r == "" || strings.Contains(r, " ") {
		return "other"
	}
	// Never use a raw request path with a client-specific suffix.
	if strings.Contains(r, "?") {
		r = strings.SplitN(r, "?", 2)[0]
	}
	if !strings.HasPrefix(r, "/") {
		return "other"
	}
	return r
}

// ApplyResult collapses a mutation outcome to a bounded label.
func ApplyResult(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "ok", "error", "conflict":
		return strings.ToLower(strings.TrimSpace(result))
	default:
		if result == "" {
			return "ok"
		}
		return "error"
	}
}
