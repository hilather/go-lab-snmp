package mibtree

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestNoWireOrControlImports(t *testing.T) {
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	forbidden := []string{
		"github.com/hilather/go-lab-snmp/internal/snmpwire",
		"github.com/hilather/go-lab-snmp/internal/snmpagent",
		"github.com/hilather/go-lab-snmp/internal/control",
		"github.com/hilather/go-lab-snmp/internal/web",
		"github.com/hilather/go-lab-snmp/internal/config",
		"net/http",
	}
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if path == bad || strings.HasPrefix(path, bad+"/") {
					t.Errorf("%s imports %s", name, path)
				}
			}
		}
	}
}
