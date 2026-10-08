package app

import (
	"context"
	"testing"
	"time"

	"github.com/hilather/go-lab-snmp/internal/domainerr"
	"github.com/hilather/go-lab-snmp/internal/model"
)

func trapPolicyChange(rev model.Revision, key string) ChangeIn {
	tp := model.TrapStoreSpec{
		MaxMessages: 1000,
		MaxBytes:    16 << 20,
		FullPolicy:  model.FullPolicyEvictOldest,
		MaxWait:     80 * time.Millisecond,
		RawRetain:   true,
	}
	return ChangeIn{
		ExpectedRevision: rev,
		IdempotencyKey:   key,
		Reason:           "idemp",
		Operations:       []model.Operation{{Op: model.OpReplaceTrapStorePolicy, TrapStorePolicy: &tp}},
	}
}

// TestIdempotencyRejectsRevisionMismatch asserts a reused key with a
// different expectedRevision is not a cache hit. The original revision
// still replays the cached apply.
func TestIdempotencyRejectsRevisionMismatch(t *testing.T) {
	svc, snap := mustBoot(t)
	in := trapPolicyChange(snap.Revision, "idemp-rev")
	first, err := svc.Apply(context.Background(), actor(), in)
	if err != nil {
		t.Fatal(err)
	}
	in.ExpectedRevision = "sha256:deadbeef"
	_, err = svc.Apply(context.Background(), actor(), in)
	if err == nil {
		t.Fatal("idempotency replay with a different expectedRevision returned the cached success")
	}
	de, ok := domainerr.As(err)
	if !ok || de.Code != domainerr.CodeIdempotencyConflict {
		t.Fatalf("err=%v want idempotency_conflict", err)
	}
	in.ExpectedRevision = snap.Revision
	again, err := svc.Apply(context.Background(), actor(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Applied || again.RuntimeRevision != first.RuntimeRevision {
		t.Fatalf("original expectedRevision must replay the cached apply: %+v", again)
	}
}
