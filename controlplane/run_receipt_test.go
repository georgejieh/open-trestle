package controlplane

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReviewRunReceiptExposesCanonicalSecretFreeState(t *testing.T) {
	journal := NewMemoryRunJournal()
	coordinator, _ := NewCoordinator(journal)
	plan := runPlanFixture(t)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(110))
	lease, _, _ := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker-secret", time.UnixMilli(200))
	_, state, err := coordinator.Resume(context.Background(), plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := NewReviewRunReceipt(state)
	if err != nil || receipt.Identity() == "" || receipt.PlanIdentity() != plan.Identity() || receipt.Status() != ReviewRunActive || receipt.Revision() != state.Revision() || receipt.TaskCount() != plan.TaskCount() || receipt.Validate() != nil {
		t.Fatalf("receipt=(%#v,%v)", receipt, err)
	}
	encoded, err := EncodeReviewRunReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("worker-secret")) || bytes.Contains(encoded, []byte(lease.token)) || bytes.Contains(encoded, []byte(lease.tokenIdentity)) {
		t.Fatalf("receipt leaked lease material: %s", encoded)
	}
	parsed, err := ParseReviewRunReceipt(encoded)
	if err != nil || parsed.Identity() != receipt.Identity() || !bytes.Equal(encoded, mustEncodeRunReceipt(t, parsed)) {
		t.Fatalf("parsed=(%#v,%v)", parsed, err)
	}
	task, exists := receipt.Task("source")
	if !exists || task.Status() != TaskRuntimeLeased || task.Attempts() != 1 || task.LeaseExpiresAt().IsZero() {
		t.Fatalf("task=(%#v,%t)", task, exists)
	}
}
func TestParseReviewRunReceiptRejectsUnknownAndTampered(t *testing.T) {
	journal := NewMemoryRunJournal()
	coordinator, _ := NewCoordinator(journal)
	plan := runPlanFixture(t)
	state, _ := coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	receipt, _ := NewReviewRunReceipt(state)
	encoded := mustEncodeRunReceipt(t, receipt)
	unknown := bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":1,"extra":true`), 1)
	tampered := bytes.Replace(encoded, []byte(`"identity":"`), []byte(`"identity":"f`), 1)
	for _, content := range [][]byte{unknown, tampered} {
		if parsed, err := ParseReviewRunReceipt(content); err == nil || parsed.Identity() != "" {
			t.Fatalf("parsed=(%#v,%v)", parsed, err)
		}
	}
	forged := receipt
	forged.identity = strings.Repeat("f", 64)
	if !errors.Is(forged.Validate(), ErrInvalidReviewRunReceiptIdentity) {
		t.Fatal("forged receipt accepted")
	}
}
func mustEncodeRunReceipt(t *testing.T, receipt ReviewRunReceipt) []byte {
	t.Helper()
	encoded, err := EncodeReviewRunReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
