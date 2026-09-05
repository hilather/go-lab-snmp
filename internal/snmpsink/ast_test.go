package snmpsink

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestInformAckUsesWriteToNotDial(t *testing.T) {
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var sawWriteTo bool
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				switch fun := x.Fun.(type) {
				case *ast.SelectorExpr:
					if fun.Sel == nil {
						return true
					}
					switch fun.Sel.Name {
					case "WriteTo":
						sawWriteTo = true
					case "Dial", "DialTimeout", "DialContext":
						t.Errorf("%s references %s", name, fun.Sel.Name)
					}
				case *ast.Ident:
					switch fun.Name {
					case "Dial", "DialTimeout", "DialContext":
						t.Errorf("%s references %s", name, fun.Name)
					}
				}
			case *ast.SelectorExpr:
				if x.Sel != nil && x.Sel.Name == "Dialer" {
					if id, ok := x.X.(*ast.Ident); ok && id.Name == "net" {
						t.Errorf("%s references net.Dialer", name)
					}
				}
			}
			return true
		})
	}
	if !sawWriteTo {
		t.Fatal("INFORM ack must WriteTo on the trap socket")
	}
}
