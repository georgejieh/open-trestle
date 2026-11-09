package controlplane

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// An event without counts must not parse with an inserted all-zero
// context_shortfall object: the bytes would differ from the canonical form
// while the derived identity stayed the same.
func TestParseRunEventRejectsZeroContextShortfall(t *testing.T) {
	ctx := context.Background()
	journal, err := NewFileRunJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	plan := inventoryPlan(t, "tenant", "repository", "run-zero-shortfall")
	coordinator := inventoryOpen(t, journal, plan)
	lease := inventoryPreparedLease(t, coordinator, plan)
	contextTask, _ := plan.Task("context")
	refusal, err := NewContextTaskRefusal(TaskFailureReasonNoEligibleRoute, TaskFailureContextShortfall{}, plan, contextTask)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.CompleteTask(ctx, plan, lease, refusal, time.UnixMilli(500)); err != nil {
		t.Fatal(err)
	}
	events, err := journal.Read(ctx, plan.Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	zero := []byte(`,"context_shortfall":{"required_tokens":0,"estimated_input_tokens":0,"max_output_tokens":0,"declared_context_tokens":0},"retry_at_milliseconds"`)
	versions := map[int]bool{}
	for _, event := range events {
		encoded, err := EncodeRunEvent(event)
		if err != nil {
			t.Fatal(err)
		}
		if parsed, err := ParseRunEvent(encoded); err != nil || parsed.Identity() != event.Identity() {
			t.Fatalf("%s: canonical event refused: %v", event.Kind(), err)
		}
		versions[runEventVersion(event)] = true
		forged := bytes.Replace(encoded, []byte(`,"retry_at_milliseconds"`), zero, 1)
		if bytes.Equal(forged, encoded) {
			t.Fatalf("%s: forgery did not apply", event.Kind())
		}
		if _, err := ParseRunEvent(forged); err == nil {
			t.Fatalf("%s (v%d): zero context_shortfall accepted", event.Kind(), runEventVersion(event))
		}
	}
	if !versions[7] || len(versions) < 2 {
		t.Fatalf("fixture covers versions %v", versions)
	}
}
