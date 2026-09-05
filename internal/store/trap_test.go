package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func rec(id, pdu, notif string, raw []byte) TrapRecord {
	return TrapRecord{
		ID:              id,
		PDUType:         pdu,
		Version:         model.VersionV2c,
		Community:       "public",
		NotificationOID: notif,
		Raw:             raw,
	}
}

func TestInsertAssignsULID(t *testing.T) {
	r := NewTrapRing(TrapPolicy{MaxMessages: 8, MaxBytes: 4096})
	id, err := r.Insert(rec("", "trapv2", "1.3.6.1.6.3.1.1.5.1", []byte("abc")))
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 26 {
		t.Fatalf("ulid len %d %q", len(id), id)
	}
	got, err := r.Get(id)
	if err != nil || got.Community != "public" || string(got.Raw) != "abc" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestWaitExisting(t *testing.T) {
	r := NewTrapRing(TrapPolicy{MaxMessages: 8, MaxBytes: 4096, MaxWait: time.Second})
	id, err := r.Insert(rec("", "inform", "1.3.6.1.6.3.1.1.5.1", []byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := r.Wait(ctx, TrapFilter{PDUType: "inform"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != id {
		t.Fatalf("id %s want %s", got.ID, id)
	}
}

func TestWaitInserted(t *testing.T) {
	r := NewTrapRing(TrapPolicy{MaxMessages: 8, MaxBytes: 4096, MaxWait: 2 * time.Second})
	errc := make(chan error, 1)
	var got *TrapRecord
	go func() {
		rec, err := r.Wait(context.Background(), TrapFilter{NotificationOID: "1.3.6.1.6.3.1.1.5.3"}, time.Second)
		got = rec
		errc <- err
	}()
	time.Sleep(20 * time.Millisecond)
	id, err := r.Insert(rec("", "trapv2", "1.3.6.1.6.3.1.1.5.3", []byte("linkdown")))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not return")
	}
	if got == nil || got.ID != id {
		t.Fatalf("%+v want %s", got, id)
	}
}

func TestReplaceCapsUpdatesMaxWait(t *testing.T) {
	r := NewTrapRing(TrapPolicy{MaxMessages: 8, MaxBytes: 4096, MaxWait: time.Second})
	if err := r.ReplaceCaps(TrapPolicy{MaxMessages: 8, MaxBytes: 4096, MaxWait: 50 * time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	if r.Policy().MaxWait != 50*time.Millisecond {
		t.Fatalf("maxWait %s", r.Policy().MaxWait)
	}
	start := time.Now()
	_, err := r.Wait(context.Background(), TrapFilter{PDUType: "inform"}, time.Second)
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeWaitTimeout {
		t.Fatalf("err=%v", err)
	}
	if time.Since(start) > 400*time.Millisecond {
		t.Fatalf("wait used old ceiling: %s", time.Since(start))
	}
}

func TestWaitTimeout(t *testing.T) {
	r := NewTrapRing(TrapPolicy{MaxMessages: 8, MaxBytes: 4096, MaxWait: 50 * time.Millisecond})
	_, err := r.Wait(context.Background(), TrapFilter{PDUType: "inform"}, 20*time.Millisecond)
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeWaitTimeout {
		t.Fatalf("err=%v", err)
	}
}

func TestWaitWipe(t *testing.T) {
	r := NewTrapRing(TrapPolicy{MaxMessages: 8, MaxBytes: 4096, MaxWait: 2 * time.Second})
	errc := make(chan error, 1)
	go func() {
		_, err := r.Wait(context.Background(), TrapFilter{PDUType: "trapv1"}, time.Second)
		errc <- err
	}()
	time.Sleep(20 * time.Millisecond)
	r.Wipe()
	select {
	case err := <-errc:
		de, ok := domainerr.As(err)
		if !ok || de.Code != domainerr.CodeStoreWiped {
			t.Fatalf("err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not return after wipe")
	}
	if r.Stats().Messages != 0 {
		t.Fatalf("stats %+v", r.Stats())
	}
}

func TestEvictOldest(t *testing.T) {
	r := NewTrapRing(TrapPolicy{MaxMessages: 2, MaxBytes: 4096, FullPolicy: model.FullPolicyEvictOldest})
	a, _ := r.Insert(rec("", "trapv2", "a", []byte("1")))
	b, _ := r.Insert(rec("", "trapv2", "b", []byte("2")))
	c, err := r.Insert(rec("", "trapv2", "c", []byte("3")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(a); err == nil {
		t.Fatal("oldest must be evicted")
	}
	if _, err := r.Get(b); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(c); err != nil {
		t.Fatal(err)
	}
}

func TestRejectFull(t *testing.T) {
	r := NewTrapRing(TrapPolicy{MaxMessages: 1, MaxBytes: 4096, FullPolicy: model.FullPolicyReject})
	id, err := r.Insert(rec("", "trapv2", "a", []byte("keep")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Insert(rec("", "trapv2", "b", []byte("nope"))); err == nil {
		t.Fatal("reject must fail the second insert")
	}
	if r.Stats().Dropped < 1 {
		t.Fatal("dropped")
	}
	got, err := r.Get(id)
	if err != nil || string(got.Raw) != "keep" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestRejectOversizedDoesNotWipe(t *testing.T) {
	r := NewTrapRing(TrapPolicy{MaxMessages: 8, MaxBytes: 8, FullPolicy: model.FullPolicyEvictOldest})
	id, err := r.Insert(rec("", "trapv2", "small", []byte("ok")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Insert(rec("", "trapv2", "huge", []byte("0123456789"))); err == nil {
		t.Fatal("oversized must reject")
	}
	got, err := r.Get(id)
	if err != nil || string(got.Raw) != "ok" {
		t.Fatalf("inbox wiped: %+v %v", got, err)
	}
}

func TestWaitFilterSince(t *testing.T) {
	clk := time.Unix(1_700_000_000, 0)
	r := NewTrapRing(TrapPolicy{MaxMessages: 8, MaxBytes: 4096, MaxWait: time.Second})
	r.SetClock(func() time.Time { return clk })
	_, _ = r.Insert(rec("", "trapv2", "old", []byte("a")))
	clk = clk.Add(time.Second)
	id, _ := r.Insert(rec("", "trapv2", "new", []byte("b")))
	got, err := r.Wait(context.Background(), TrapFilter{Since: time.Unix(1_700_000_000, 0)}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != id {
		t.Fatalf("since picked %s want %s", got.ID, id)
	}
}

func TestWaitTimeoutCode(t *testing.T) {
	err := domainerr.New(domainerr.CodeWaitTimeout, "wait timed out")
	if !errors.Is(err, domainerr.New(domainerr.CodeWaitTimeout, "x")) {
		t.Fatal(err)
	}
	if !strings.Contains(err.Error(), "wait_timeout") {
		t.Fatalf("%v", err)
	}
}
