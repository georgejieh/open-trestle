package controlplane

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/schemacheck"
)

// A context task refused before any model effect records a closed route
// reason and, for route_context_insufficient, its content-free counts, through
// the completion wire, the durable v7 event, replay and the v3 receipt.
func TestContextTaskRefusalRecordsTheRouteShortfall(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := inventoryPlan(t, "tenant", "repository", "run-refusal")
	coordinator := inventoryOpen(t, journal, plan)
	lease := inventoryPreparedLease(t, coordinator, plan)
	contextTask, _ := plan.Task("context")
	source, _ := plan.Task("source")
	shortfall := TaskFailureContextShortfall{RequiredTokens: 14096, EstimatedInputTokens: 10000, MaxOutputTokens: 4096, DeclaredContextTokens: 8192}
	for name, build := range map[string]func() (TaskCompletion, error){
		"counts without the reason": func() (TaskCompletion, error) {
			return NewContextTaskRefusal(TaskFailureReasonNoEligibleRoute, shortfall, plan, contextTask)
		},
		"reason without counts": func() (TaskCompletion, error) {
			return NewContextTaskRefusal(TaskFailureReasonRouteContextInsufficient, TaskFailureContextShortfall{}, plan, contextTask)
		},
		"inconsistent counts": func() (TaskCompletion, error) {
			s := shortfall
			s.RequiredTokens++
			return NewContextTaskRefusal(TaskFailureReasonRouteContextInsufficient, s, plan, contextTask)
		},
		"declared above the need": func() (TaskCompletion, error) {
			s := shortfall
			s.DeclaredContextTokens = 20000
			return NewContextTaskRefusal(TaskFailureReasonRouteContextInsufficient, s, plan, contextTask)
		},
		"source reason on context": func() (TaskCompletion, error) {
			return NewContextTaskRefusal(TaskFailureReasonNoMergeBase, TaskFailureContextShortfall{}, plan, contextTask)
		},
		"context reason on source": func() (TaskCompletion, error) {
			return NewContextTaskRefusal(TaskFailureReasonNoEligibleRoute, TaskFailureContextShortfall{}, plan, source)
		},
		"source constructor, context": func() (TaskCompletion, error) {
			return NewSourceTaskFailureWithReason(RunFailurePolicy, TaskFailureReasonNoEligibleRoute, plan, source)
		},
	} {
		if _, err := build(); err == nil {
			t.Fatalf("%s: refusal accepted", name)
		}
	}
	completion, err := NewContextTaskRefusal(TaskFailureReasonRouteContextInsufficient, shortfall, plan, contextTask)
	if err != nil || completion.Validate() != nil || completion.Failure() != RunFailurePolicy {
		t.Fatalf("completion: %v", err)
	}
	encoded, err := EncodeTaskCompletion(completion)
	if err != nil || !bytes.Contains(encoded, []byte(`"failure_reason":"route_context_insufficient","context_shortfall":{"required_tokens":14096,"estimated_input_tokens":10000,"max_output_tokens":4096,"declared_context_tokens":8192}`)) {
		t.Fatalf("completion wire=%s err=%v", encoded, err)
	}
	if parsed, err := ParseTaskCompletion(encoded); err != nil || parsed.Identity() != completion.Identity() {
		t.Fatalf("completion readback: %v", err)
	} else if got, ok := parsed.ContextShortfall(); !ok || got != shortfall {
		t.Fatal("completion readback lost the counts")
	}
	if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, time.UnixMilli(500)); err != nil {
		t.Fatal(err)
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
	runtime, _ := state.Task("context")
	if got, ok := runtime.ContextShortfall(); runtime.Status() != TaskRuntimeFailed || runtime.Failure() != RunFailurePolicy || runtime.FailureReason() != TaskFailureReasonRouteContextInsufficient || !ok || got != shortfall || !runtime.RetryAt().IsZero() {
		t.Fatalf("replayed runtime status=%s reason=%s", runtime.Status(), runtime.FailureReason())
	}
	events, err := reopened.Read(ctx, plan.Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	encodedEvent, err := EncodeRunEvent(events[len(events)-1])
	if err != nil || !bytes.Contains(encodedEvent, []byte(`"schema_version":7`)) || !bytes.Contains(encodedEvent, []byte(`"context_shortfall":{"required_tokens":14096`)) {
		t.Fatalf("event=%s err=%v", encodedEvent, err)
	}
	if parsed, err := ParseRunEvent(encodedEvent); err != nil || parsed.Identity() != events[len(events)-1].Identity() {
		t.Fatalf("event readback: %v", err)
	}
	tampered := bytes.Replace(encodedEvent, []byte(`"declared_context_tokens":8192`), []byte(`"declared_context_tokens":8193`), 1)
	if _, err := ParseRunEvent(tampered); err == nil {
		t.Fatal("tampered counts kept the event identity")
	}
	receipt, err := NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	encodedReceipt, err := EncodeReviewRunReceipt(receipt)
	if err != nil || !bytes.Contains(encodedReceipt, []byte(`"schema_version":3`)) || !bytes.Contains(encodedReceipt, []byte(`"failure_reason":"route_context_insufficient","context_shortfall":{"required_tokens":14096`)) {
		t.Fatalf("receipt=%s err=%v", encodedReceipt, err)
	}
	parsedReceipt, err := ParseReviewRunReceipt(encodedReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if task, ok := parsedReceipt.Task("context"); !ok {
		t.Fatal("receipt lost the context task")
	} else if got, present := task.ContextShortfall(); !present || got != shortfall || task.FailureReason() != TaskFailureReasonRouteContextInsufficient {
		t.Fatal("receipt readback lost the counts")
	}
	registry, err := schemacheck.Load(filepath.Join("..", "schemas"))
	if err != nil {
		t.Fatal(err)
	}
	for id, value := range map[string][]byte{
		"urn:open-trestle:schema:controlplane:review-task-completion:v3": encoded,
		"urn:open-trestle:schema:controlplane:review-run-event:v7":       encodedEvent,
		"urn:open-trestle:schema:controlplane:review-run-receipt:v3":     encodedReceipt,
	} {
		if err := registry.Validate(id, value); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
}
