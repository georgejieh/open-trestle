package controlplane

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A failed source attempt records a closed, content-free reason that survives
// the durable journal, replay, the public receipt, and the worker wire.
func TestSourceTaskFailureReasonIsRecordedAndReadBack(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := inventoryPlan(t, "tenant", "repository", "run-reason")
	coordinator := inventoryOpen(t, journal, plan)
	source, _ := plan.Task("source")
	lease, ok, err := coordinator.ClaimTask(ctx, plan, "source", source.HandlerIdentity(), "worker", time.UnixMilli(200))
	if err != nil || !ok {
		t.Fatalf("claim: %v", err)
	}
	completion, err := NewSourceTaskFailureWithReason(RunFailurePolicy, TaskFailureReasonNoMergeBase, plan, source)
	if err != nil || completion.Validate() != nil || completion.FailureReason() != TaskFailureReasonNoMergeBase {
		t.Fatalf("completion: %v", err)
	}
	encodedCompletion, err := EncodeTaskCompletion(completion)
	if err != nil || !bytes.Contains(encodedCompletion, []byte(`"schema_version":3`)) || !bytes.Contains(encodedCompletion, []byte(`"failure_reason":"no_merge_base"`)) {
		t.Fatalf("completion wire=%s err=%v", encodedCompletion, err)
	}
	if parsed, err := ParseTaskCompletion(encodedCompletion); err != nil || parsed.Identity() != completion.Identity() || parsed.FailureReason() != TaskFailureReasonNoMergeBase {
		t.Fatalf("completion readback: %v", err)
	}
	if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, time.UnixMilli(201)); err != nil {
		t.Fatal(err)
	}
	if again, err := coordinator.CompleteTask(ctx, plan, lease, completion, time.UnixMilli(202)); err != nil {
		t.Fatalf("idempotent completion refused: %v", err)
	} else if task, _ := again.Task("source"); task.FailureReason() != TaskFailureReasonNoMergeBase {
		t.Fatal("idempotent completion lost the reason")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	readback, err := NewCoordinator(reopened)
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := readback.Resume(ctx, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := state.Task("source")
	if runtime.Status() != TaskRuntimeFailed || runtime.Failure() != RunFailurePolicy || runtime.FailureReason() != TaskFailureReasonNoMergeBase || runtime.OutputIdentity() != "" {
		t.Fatalf("replayed runtime status=%s failure=%s reason=%s", runtime.Status(), runtime.Failure(), runtime.FailureReason())
	}
	events, err := reopened.Read(ctx, plan.Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	failed := events[len(events)-1]
	encodedEvent, err := EncodeRunEvent(failed)
	if err != nil || failed.Kind() != RunEventTaskFailed || !bytes.Contains(encodedEvent, []byte(`"schema_version":7`)) || !bytes.Contains(encodedEvent, []byte(`"failure_reason":"no_merge_base"`)) {
		t.Fatalf("event=%s err=%v", encodedEvent, err)
	}
	receipt, err := NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	encodedReceipt, err := EncodeReviewRunReceipt(receipt)
	if err != nil || !bytes.Contains(encodedReceipt, []byte(`"schema_version":3`)) || !bytes.Contains(encodedReceipt, []byte(`"failure_reason":"no_merge_base"`)) {
		t.Fatalf("receipt=%s err=%v", encodedReceipt, err)
	}
	parsedReceipt, err := ParseReviewRunReceipt(encodedReceipt)
	if err != nil || parsedReceipt.Identity() != receipt.Identity() {
		t.Fatalf("receipt readback: %v", err)
	}
	if task, _ := parsedReceipt.Task("source"); task.FailureReason() != TaskFailureReasonNoMergeBase {
		t.Fatal("receipt lost the reason")
	}
	for _, mutated := range [][]byte{
		bytes.Replace(encodedReceipt, []byte(`"schema_version":3`), []byte(`"schema_version":1`), 1),
		bytes.Replace(encodedReceipt, []byte(`"no_merge_base"`), []byte(`"unrelated_text"`), 1),
	} {
		if _, err := ParseReviewRunReceipt(mutated); err == nil {
			t.Fatal("receipt accepted a mismatched version or unknown reason")
		}
	}
	schemas := filepath.Join("..", "schemas", "controlplane")
	assertSchemaRecordShape(t, filepath.Join(schemas, "review-task-completion-v3.schema.json"), encodedCompletion)
	assertSchemaRecordShape(t, filepath.Join(schemas, "review-run-event-v7.schema.json"), encodedEvent)
	assertSchemaRecordShape(t, filepath.Join(schemas, "review-run-receipt-v3.schema.json"), encodedReceipt)
	if _, err := ParseRunEvent(bytes.Replace(encodedEvent, []byte(`"schema_version":7`), []byte(`"schema_version":1`), 1)); err == nil {
		t.Fatal("event accepted a reason under version 1")
	}
}

func TestTaskFailureReasonIsSourceOnly(t *testing.T) {
	ctx := context.Background()
	plan := inventoryPlan(t, "tenant", "repository", "run-reason-scope")
	change, _ := plan.Task("change")
	if _, err := NewSourceTaskFailureWithReason(RunFailurePolicy, TaskFailureReasonNoMergeBase, plan, change); !errors.Is(err, ErrInvalidTaskCompletion) {
		t.Fatalf("non-source reason err=%v", err)
	}
	source, _ := plan.Task("source")
	for _, reason := range []TaskFailureReason{0, TaskFailureReasonMergeBaseUnavailable + 1} {
		if _, err := NewSourceTaskFailureWithReason(RunFailurePolicy, reason, plan, source); err == nil {
			t.Fatalf("invalid reason %d accepted", reason)
		}
	}
	other := inventoryPlan(t, "tenant", "repository", "run-reason-other")
	foreign, err := NewSourceTaskFailureWithReason(RunFailurePolicy, TaskFailureReasonNothingToReview, other, source)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := NewFileRunJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	coordinator := inventoryOpen(t, journal, plan)
	lease, ok, err := coordinator.ClaimTask(ctx, plan, "source", source.HandlerIdentity(), "worker", time.UnixMilli(200))
	if err != nil || !ok {
		t.Fatalf("claim: %v", err)
	}
	if _, err := coordinator.CompleteTask(ctx, plan, lease, foreign, time.UnixMilli(201)); !errors.Is(err, ErrInvalidTaskCompletion) {
		t.Fatalf("reason bound to another plan err=%v", err)
	}
	for _, reason := range []string{"no_merge_base", "nothing_to_review", "merge_base_unavailable"} {
		if parsed, err := ParseTaskFailureReason(reason); err != nil || parsed.String() != reason {
			t.Fatalf("reason %s: %v", reason, err)
		}
	}
	if _, err := ParseTaskFailureReason(strings.ToUpper("no_merge_base")); err == nil {
		t.Fatal("reason parsing is not exact")
	}
}
