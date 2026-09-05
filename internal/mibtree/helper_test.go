package mibtree

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/model"
	"gopkg.in/yaml.v3"
)

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

func mustOID(t *testing.T, s string) OID {
	t.Helper()
	oid, err := ParseOID(s)
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

func oid(arcs ...uint32) OID {
	out := make(OID, len(arcs))
	copy(out, arcs)
	return out
}

type mapRange struct {
	Min int64 `yaml:"min"`
	Max int64 `yaml:"max"`
}

type mapObject struct {
	OID       string    `yaml:"oid"`
	Name      string    `yaml:"name"`
	Type      string    `yaml:"type"`
	Access    string    `yaml:"access"`
	Value     any       `yaml:"value"`
	ValueFrom string    `yaml:"valueFrom"`
	Range     *mapRange `yaml:"range"`
	Size      *mapRange `yaml:"size"`
}

func loadMapFile(t *testing.T, name string) (string, []model.Object) {
	t.Helper()
	path := filepath.Join(repoRoot(t), "testdata", "maps", name)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Name    string      `yaml:"name"`
		Objects []mapObject `yaml:"objects"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	out := make([]model.Object, len(doc.Objects))
	for i, o := range doc.Objects {
		out[i] = model.Object{
			OID:       o.OID,
			Name:      o.Name,
			Type:      o.Type,
			Access:    o.Access,
			Value:     o.Value,
			ValueFrom: o.ValueFrom,
		}
		if o.Range != nil {
			r := model.RangeSpec{Min: o.Range.Min, Max: o.Range.Max}
			out[i].Range = &r
		}
		if o.Size != nil {
			s := model.RangeSpec{Min: o.Size.Min, Max: o.Size.Max}
			out[i].Size = &s
		}
	}
	return doc.Name, out
}

func mustCompileFile(t *testing.T, name string) *Tree {
	t.Helper()
	_, objs := loadMapFile(t, name)
	tree, err := Compile(objs)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func walkAll(t *Tree) []string {
	var out []string
	var oid OID
	seen := map[string]bool{}
	for {
		r := t.GetNext(oid)
		if r.Exception == EndOfMibView {
			return out
		}
		if r.Exception != NoException {
			return out
		}
		key := r.OID.String()
		if seen[key] {
			return out
		}
		seen[key] = true
		out = append(out, key)
		oid = r.OID
	}
}

func obj(oid, typ, access string, value any) model.Object {
	return model.Object{OID: oid, Type: typ, Access: access, Value: value}
}
