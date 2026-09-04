package config

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

var reservedPrefixes = []struct {
	prefix string
	why    string
}{
	{"forward", "implies trap forwarding"},
	{"relay", "implies trap relay"},
	{"remote", "implies a remote manager/agent surface"},
	{"destination", "implies a trap destination"},
	{"trapdest", "implies a trap destination"},
	{"notifytarget", "implies a notification target"},
	{"proxy", "implies SNMP proxy"},
	{"manager", "implies an SNMP manager"},
	{"agentx", "implies AgentX"},
	{"smux", "implies SMUX"},
	{"netsnmp", "implies wrapping net-snmp"},
	{"snmpd", "implies wrapping snmpd"},
}

var knownWireNames = sync.OnceValue(func() map[string]bool {
	out := map[string]bool{}
	collectJSONNames(reflect.TypeOf(model.State{}), out)
	return out
})

func collectJSONNames(typ reflect.Type, out map[string]bool) {
	if typ == nil {
		return
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		if typ == reflect.TypeOf(time.Time{}) {
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if f.PkgPath != "" {
				continue
			}
			tag := f.Tag.Get("json")
			name, _, _ := strings.Cut(tag, ",")
			if name == "" || name == "-" {
				continue
			}
			out[name] = true
			collectJSONNames(f.Type, out)
		}
	case reflect.Slice, reflect.Array, reflect.Map:
		collectJSONNames(typ.Elem(), out)
	}
}

func normalizeKey(k string) string {
	k = strings.TrimLeft(k, "-")
	var b strings.Builder
	b.Grow(len(k))
	for _, r := range k {
		if r == '-' || r == '_' {
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

func reservedReason(normalized, original string) string {
	if knownWireNames()[original] {
		return ""
	}
	for _, p := range reservedPrefixes {
		if strings.HasPrefix(normalized, p.prefix) {
			return p.why
		}
	}
	return ""
}

func isFreeFormStringMap(path string) bool {
	return path == "metadata.labels" || strings.HasSuffix(path, ".labels")
}

func reservedFields(v any, path string) []domainerr.FieldViolation {
	switch x := v.(type) {
	case map[string]any:
		if isFreeFormStringMap(path) {
			return nil
		}
		var vs []domainerr.FieldViolation
		for k, child := range x {
			p := joinPath(path, k)
			if why := reservedReason(normalizeKey(k), k); why != "" {
				vs = append(vs, domainerr.FieldViolation{
					Path:    p,
					Code:    violationReservedKey,
					Message: fmt.Sprintf("reserved key %q %s — not a LabSNMP surface", k, why),
				})
				continue
			}
			vs = append(vs, reservedFields(child, p)...)
		}
		return vs
	case []any:
		var vs []domainerr.FieldViolation
		for i, child := range x {
			vs = append(vs, reservedFields(child, indexPath(path, i))...)
		}
		return vs
	default:
		return nil
	}
}
