package testutil

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var productionDialPackages = []string{
	"internal/snmpwire",
	"internal/mibtree",
	"internal/usm",
	"internal/snmpagent",
	"internal/snmpsink",
	"internal/store",
	"internal/app",
}

var forbiddenModules = []string{
	"github.com/gosnmp/gosnmp",
	"github.com/sleepinggenius2/gosmi",
	"github.com/k-sone/snmpgo",
}

var forbiddenExec = map[string]bool{
	"snmpd": true, "snmptrapd": true, "snmpget": true,
	"snmpwalk": true, "snmptrap": true, "snmpinform": true,
}

func moduleRoot(t *testing.T) string {
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

func TestGoModNoGosnmp(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(moduleRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "gosnmp") {
		t.Fatal("gosnmp must not appear in go.mod")
	}
}

func TestForbiddenModules(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "vendor", "node_modules", "dist", "go-lab-snmp-design-pack":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		for _, imp := range f.Imports {
			ipath := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbiddenModules {
				if ipath == bad || strings.HasPrefix(ipath, bad+"/") {
					t.Errorf("%s imports forbidden module %s", rel, ipath)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNoDialOnProductionPackages(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	for _, rel := range productionDialPackages {
		dir := filepath.Join(root, filepath.FromSlash(rel))
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			fileRel, _ := filepath.Rel(root, path)
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					switch fun := x.Fun.(type) {
					case *ast.SelectorExpr:
						if fun.Sel == nil {
							return true
						}
						switch fun.Sel.Name {
						case "Dial", "DialTimeout", "DialContext":
							t.Errorf("%s references %s", fileRel, fun.Sel.Name)
						}
					case *ast.Ident:
						switch fun.Name {
						case "Dial", "DialTimeout", "DialContext":
							t.Errorf("%s references %s", fileRel, fun.Name)
						}
					}
				case *ast.SelectorExpr:
					if x.Sel != nil && x.Sel.Name == "Dialer" {
						if id, ok := x.X.(*ast.Ident); ok && id.Name == "net" {
							t.Errorf("%s references net.Dialer", fileRel)
						}
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestForbiddenExecBasenames(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "vendor", "node_modules", "dist", "go-lab-snmp-design-pack", "scripts":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			x, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fun, ok := x.Fun.(*ast.SelectorExpr)
			if !ok || fun.Sel == nil {
				return true
			}
			if fun.Sel.Name != "Command" && fun.Sel.Name != "CommandContext" {
				return true
			}
			id, ok := fun.X.(*ast.Ident)
			if !ok || id.Name != "exec" {
				return true
			}
			start := 0
			if fun.Sel.Name == "CommandContext" {
				start = 1
			}
			if start >= len(x.Args) {
				return true
			}
			lit, ok := x.Args[start].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			val := strings.Trim(lit.Value, `"`)
			base := val
			if i := strings.LastIndex(val, "/"); i >= 0 {
				base = val[i+1:]
			}
			if forbiddenExec[base] {
				t.Errorf("%s: forbidden exec %s", rel, val)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
