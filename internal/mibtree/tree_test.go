package mibtree

import (
	"errors"
	"sync"
	"testing"

	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func TestCompileEmptyMap(t *testing.T) {
	tree, err := Compile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Len() != 0 {
		t.Fatalf("len=%d", tree.Len())
	}
	empty := mustCompileFile(t, "empty.yaml")
	if empty.Len() != 0 {
		t.Fatalf("empty.yaml len=%d", empty.Len())
	}
	r := empty.Get(mustOID(t, "1.3.6"))
	if r.Exception != NoSuchObject {
		t.Fatalf("Get empty = %s", r.Exception)
	}
	n := empty.GetNext(mustOID(t, "1.3.6"))
	if n.Exception != EndOfMibView {
		t.Fatalf("GetNext empty = %s", n.Exception)
	}
}

func TestCompileDuplicateOID(t *testing.T) {
	_, err := Compile([]model.Object{
		obj("1.3.6", model.TypeInteger, model.AccessRead, int64(1)),
		obj("1.3.6", model.TypeInteger, model.AccessRead, int64(2)),
	})
	if err == nil {
		t.Fatal("expected duplicate oid error")
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeValidationFailed {
		t.Fatalf("err=%v", err)
	}
	found := false
	for _, v := range de.FieldViolations {
		if v.Code == violationDuplicateID {
			found = true
		}
	}
	if !found {
		t.Fatalf("want duplicate_id in %+v", de.FieldViolations)
	}
}

func TestCompileInvalidOID(t *testing.T) {
	_, err := Compile([]model.Object{
		obj(".1.3.6", model.TypeInteger, model.AccessRead, int64(1)),
	})
	if err == nil {
		t.Fatal("expected invalid oid")
	}
}

func TestGetHeuristics(t *testing.T) {
	tree := mustCompileFile(t, "system-if.yaml")
	sysDescr := oid(1, 3, 6, 1, 2, 1, 1, 1, 0)
	sysDescrObj := oid(1, 3, 6, 1, 2, 1, 1, 1)
	ifOperCol := oid(1, 3, 6, 1, 2, 1, 2, 2, 1, 8)
	ifOper1 := oid(1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1)

	exact := tree.Get(sysDescr)
	if exact.Exception != NoException || string(exact.Value.Bytes) != "LabSNMP public-if" {
		t.Fatalf("exact GET: %+v", exact)
	}

	prefix := tree.Get(sysDescrObj)
	if prefix.Exception != NoSuchInstance {
		t.Fatalf("prefix-of-instance = %s, want noSuchInstance", prefix.Exception)
	}
	col := tree.Get(ifOperCol)
	if col.Exception != NoSuchInstance {
		t.Fatalf("column GET = %s, want noSuchInstance", col.Exception)
	}

	under := tree.Get(append(cloneOID(sysDescr), 1))
	if under.Exception != NoSuchObject {
		t.Fatalf("GET under scalar = %s, want noSuchObject", under.Exception)
	}
	underRow := tree.Get(append(cloneOID(ifOper1), 0))
	if underRow.Exception != NoSuchObject {
		t.Fatalf("GET under row = %s, want noSuchObject", underRow.Exception)
	}

	miss := tree.Get(oid(1, 2, 3))
	if miss.Exception != NoSuchObject {
		t.Fatalf("no overlap = %s, want noSuchObject", miss.Exception)
	}
}

func TestGetUptimeIsDynamic(t *testing.T) {
	tree := mustCompileFile(t, "system-if.yaml")
	found := false
	for _, s := range walkAll(tree) {
		r := tree.Get(mustOID(t, s))
		if r.Value.ValueFrom != model.ValueFromUptime {
			continue
		}
		found = true
		if r.Exception != NoException || r.Value.Type != model.TypeTimeTicks {
			t.Fatalf("uptime GET %s = %+v", s, r)
		}
	}
	if !found {
		t.Fatal("no valueFrom uptime leaf")
	}
}

func TestCompileConfigPublicIf(t *testing.T) {
	t.Chdir(repoRoot(t))
	st, err := config.LoadFile("testdata/config/valid/full.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Spec.Maps) == 0 {
		t.Fatal("no maps")
	}
	tree, err := Compile(st.Spec.Maps[0].Objects)
	if err != nil {
		t.Fatal(err)
	}
	got := walkAll(tree)
	if len(got) != tree.Len() || tree.Len() == 0 {
		t.Fatalf("walk %d len %d", len(got), tree.Len())
	}
}

func TestGetNextFromPrefix(t *testing.T) {
	tree := mustCompileFile(t, "system-if.yaml")
	sysDescrObj := oid(1, 3, 6, 1, 2, 1, 1, 1)
	sysDescr := oid(1, 3, 6, 1, 2, 1, 1, 1, 0)
	r := tree.GetNext(sysDescrObj)
	if r.Exception != NoException || !r.OID.Equal(sysDescr) {
		t.Fatalf("GetNext column = %s %s", r.OID, r.Exception)
	}
	ifOperCol := oid(1, 3, 6, 1, 2, 1, 2, 2, 1, 8)
	ifOper1 := oid(1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1)
	col := tree.GetNext(ifOperCol)
	if col.Exception != NoException || !col.OID.Equal(ifOper1) {
		t.Fatalf("GetNext ifOperStatus = %s %s", col.OID, col.Exception)
	}
}

func TestGetNextOrderLocked(t *testing.T) {
	tree := mustCompileFile(t, "lex-order.yaml")
	got := walkAll(tree)
	want := []string{"1.3.6", "1.3.6.1", "1.3.10"}
	if len(got) != len(want) {
		t.Fatalf("walk = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("walk = %v, want %v", got, want)
		}
	}
	n := tree.GetNext(mustOID(t, "1.3.6"))
	if n.Exception != NoException || n.OID.String() != "1.3.6.1" {
		t.Fatalf("GetNext(1.3.6) = %s %s", n.OID, n.Exception)
	}
	end := tree.GetNext(mustOID(t, "1.3.10"))
	if end.Exception != EndOfMibView {
		t.Fatalf("GetNext last = %s", end.Exception)
	}
}

func TestWalkEveryLeafOnce(t *testing.T) {
	_, objs := loadMapFile(t, "system-if.yaml")
	tree, err := Compile(objs)
	if err != nil {
		t.Fatal(err)
	}
	got := walkAll(tree)
	if len(got) != tree.Len() {
		t.Fatalf("walk returned %d leaves, tree has %d", len(got), tree.Len())
	}
	seen := map[string]bool{}
	for i, s := range got {
		if seen[s] {
			t.Fatalf("duplicate leaf %s at %d", s, i)
		}
		seen[s] = true
		if i > 0 && Compare(mustOID(t, s), mustOID(t, got[i-1])) <= 0 {
			t.Fatalf("walk not strictly increasing at %s after %s", s, got[i-1])
		}
		r := tree.Get(mustOID(t, s))
		if r.Exception != NoException {
			t.Fatalf("GET %s after walk = %s", s, r.Exception)
		}
	}
	if len(seen) != len(objs) {
		t.Fatalf("walk saw %d, objects %d", len(seen), len(objs))
	}
}

func TestGetBulkNonRepeatersAndRepetitions(t *testing.T) {
	tree := mustCompileFile(t, "lex-order.yaml")
	oids := []OID{mustOID(t, "1.3"), mustOID(t, "1.3.6")}
	got := tree.GetBulk(oids, 1, 2)
	// non-repeater 1.3 → 1.3.6; repeater 1.3.6 → 1.3.6.1 then 1.3.10
	if len(got) != 3 {
		t.Fatalf("len=%d results=%v", len(got), resultsOIDs(got))
	}
	if got[0].OID.String() != "1.3.6" || got[0].Exception != NoException {
		t.Fatalf("non-repeater = %s %s", got[0].OID, got[0].Exception)
	}
	if got[1].OID.String() != "1.3.6.1" {
		t.Fatalf("rep1 = %s", got[1].OID)
	}
	if got[2].OID.String() != "1.3.10" {
		t.Fatalf("rep2 = %s", got[2].OID)
	}
}

func TestGetBulkTwoRepeaters(t *testing.T) {
	// RFC 3416 order is outer-repetition, inner-repeater. R=1 goldens
	// cannot catch a swapped nest.
	tree := mustCompileFile(t, "lex-order.yaml")
	got := tree.GetBulk([]OID{mustOID(t, "1.3"), mustOID(t, "1.3.6")}, 0, 2)
	want := []string{"1.3.6", "1.3.6.1", "1.3.6.1", "1.3.10"}
	names := resultsOIDs(got)
	if len(names) != len(want) {
		t.Fatalf("len=%d results=%v want %v", len(names), names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("results=%v want %v", names, want)
		}
	}
}

func TestGetBulkMaxRepetitionsCap(t *testing.T) {
	tree := mustCompileFile(t, "lex-order.yaml")
	got := tree.GetBulk([]OID{mustOID(t, "1.3")}, 0, 10_000)
	if len(got) != DefaultMaxRepetitions {
		t.Fatalf("capped len=%d want %d", len(got), DefaultMaxRepetitions)
	}
	end := 0
	for _, r := range got {
		if r.Exception == EndOfMibView {
			end++
		}
	}
	if end == 0 {
		t.Fatal("expected trailing endOfMibView under the cap")
	}
	tree.SetMaxRepetitions(2)
	got = tree.GetBulk([]OID{mustOID(t, "1.3")}, 0, 50)
	if len(got) != 2 {
		t.Fatalf("custom cap len=%d", len(got))
	}
}

func TestGetBulkZeroRepetitions(t *testing.T) {
	tree := mustCompileFile(t, "lex-order.yaml")
	got := tree.GetBulk([]OID{mustOID(t, "1.3"), mustOID(t, "1.3.6")}, 1, 0)
	if len(got) != 1 || got[0].OID.String() != "1.3.6" {
		t.Fatalf("maxRepetitions=0: %v", resultsOIDs(got))
	}
	empty := tree.GetBulk([]OID{mustOID(t, "1.3")}, 0, 0)
	if len(empty) != 0 {
		t.Fatalf("N=0 M=0 produced %d", len(empty))
	}
}

func TestGetBulkEndOfMibViewRepeats(t *testing.T) {
	tree := mustCompileFile(t, "lex-order.yaml")
	got := tree.GetBulk([]OID{mustOID(t, "1.3.10")}, 0, 3)
	if len(got) != 3 {
		t.Fatalf("len=%d", len(got))
	}
	for i, r := range got {
		if r.Exception != EndOfMibView {
			t.Fatalf("rep %d = %s", i, r.Exception)
		}
	}
}

func TestNilTree(t *testing.T) {
	var tree *Tree
	if tree.Len() != 0 {
		t.Fatal("nil Len")
	}
	if tree.Get(mustOID(t, "1.3.6")).Exception != NoSuchObject {
		t.Fatal("nil Get")
	}
	if tree.GetNext(mustOID(t, "1.3.6")).Exception != EndOfMibView {
		t.Fatal("nil GetNext")
	}
	if err := tree.CheckSet(mustOID(t, "1.3.6"), Value{Type: model.TypeInteger, Signed: 1}); !errors.Is(err, ErrNotWritable) {
		t.Fatalf("nil CheckSet: %v", err)
	}
}

func TestTreeConcurrentGetNext(t *testing.T) {
	tree := mustCompileFile(t, "system-if.yaml")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := walkAll(tree)
			if len(got) != tree.Len() {
				t.Errorf("walk %d want %d", len(got), tree.Len())
			}
		}()
	}
	wg.Wait()
}

func resultsOIDs(rs []Result) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		if r.Exception != NoException {
			out[i] = r.Exception.String()
			continue
		}
		out[i] = r.OID.String()
	}
	return out
}
