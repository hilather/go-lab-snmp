package app

import (
	"context"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/compiler"
	"github.com/hilather/go-lab-snmp/internal/config"
	"github.com/hilather/go-lab-snmp/internal/mibtree"
	"github.com/hilather/go-lab-snmp/internal/model"
	"github.com/hilather/go-lab-snmp/internal/snapshot"
	"github.com/hilather/go-lab-snmp/internal/snmpagent"
	"github.com/hilather/go-lab-snmp/internal/snmptest"
	"github.com/hilather/go-lab-snmp/internal/snmpwire"
	"github.com/hilather/go-lab-snmp/internal/store"
)

const rwShareYAML = `
apiVersion: labsnmp.dev/v1alpha1
kind: LabSNMP
metadata:
  name: rw
spec:
  maps:
    - name: rw
      objects:
        - oid: "1.3.6.1.2.1.1.1.0"
          type: octetString
          access: read
          value: "descr"
        - oid: "1.3.6.1.2.1.2.2.1.8.1"
          type: integer
          access: write
          value: 1
          range: { min: 1, max: 7 }
  communities:
    - name: public
      communityFile: testdata/secrets/snmp-public
      versions: [v1, v2c]
      access: read
      map: rw
    - name: private
      communityFile: testdata/secrets/snmp-private
      versions: [v1, v2c]
      access: read-write
      map: rw
`

func TestSetOIDAndSNMPSETShareOverlay(t *testing.T) {
	t.Chdir(repoRoot(t))
	st, err := config.Load([]byte(rwShareYAML))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := compiler.Compile(st, compiler.CompileOpts{BaseDir: repoRoot(t)})
	if err != nil {
		t.Fatal(err)
	}
	snaps := snapshot.NewStore()
	snaps.InstallBootstrap(snap)
	ov := store.NewOverlay()
	svc := New(Options{Snapshots: snaps, Overlay: ov, BootstrapPath: "testdata/config/valid/full.yaml"})
	agent, err := snmpagent.New(snmpagent.Config{
		Addr:    "127.0.0.1:0",
		Store:   snaps,
		Overlay: ov,
		Queries: store.NewQueryRing(8),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = agent.Shutdown(ctx)
	})

	a := actor()
	oid := "1.3.6.1.2.1.2.2.1.8.1"
	if _, err := svc.SetOID(context.Background(), a, OIDSetIn{
		Map:   "rw",
		OID:   oid,
		Value: mibtree.Value{Type: model.TypeInteger, Signed: 2},
	}); err != nil {
		t.Fatal(err)
	}
	host := agent.Addr().String()
	req := snmptest.MustEncodeGet(t, snmpwire.VersionV2c, "private", 1, snmpwire.OID{1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1})
	m := snmptest.MustExchange(t, host, req, 2*time.Second)
	p := m.RequestPDU()
	if p == nil || p.VarBinds[0].Value.Int != 2 {
		t.Fatalf("SNMP GET after oids:set: %+v", p)
	}

	set := snmptest.MustEncodeSet(t, snmpwire.VersionV2c, "private", 2, []snmpwire.VarBind{{
		Name:  snmpwire.OID{1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1},
		Value: snmpwire.Int(3),
	}})
	m = snmptest.MustExchange(t, host, set, 2*time.Second)
	if p = m.RequestPDU(); p == nil || p.ErrorStatus != snmpwire.ErrorStatusNoError {
		t.Fatalf("SNMP SET: %+v", p)
	}
	got, err := svc.GetOID(context.Background(), a, OIDGetIn{Map: "rw", OID: oid})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Overlay || got.Value.Signed != 3 {
		t.Fatalf("GetOID after SNMP SET: %+v", got)
	}
}
