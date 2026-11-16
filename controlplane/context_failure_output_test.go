package controlplane

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestContextFailureOutputLinksOnlyContextTaskAndReplays(t *testing.T) {
	ctx := context.Background()
	journal := NewMemoryRunJournal()
	coordinator, _ := NewCoordinator(journal)
	plan := runPlanFixture(t)
	_, err := coordinator.Open(ctx, plan, time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	at := int64(200)
	for _, key := range []string{"source", "change", "analysis", "memory"} {
		task, _ := plan.Task(key)
		lease, claimed, err := coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", time.UnixMilli(at))
		if err != nil || !claimed {
			t.Fatalf("claim %s: %v", key, err)
		}
		success, _ := NewTaskSuccess(strings.Repeat("e", 64))
		_, err = coordinator.CompleteTask(ctx, plan, lease, success, time.UnixMilli(at+1))
		if err != nil {
			t.Fatal(err)
		}
		at += 20
	}
	task, _ := plan.Task("context")
	lease, claimed, err := coordinator.ClaimTask(ctx, plan, task.Key(), task.HandlerIdentity(), "worker", time.UnixMilli(at))
	if err != nil || !claimed {
		t.Fatalf("claim context: %v", err)
	}
	output := strings.Repeat("a", 64)
	completion, err := NewContextTaskFailureWithOutput(RunFailurePolicy, plan, task, output)
	if err != nil || completion.OutputIdentity() != output {
		t.Fatalf("completion: %v", err)
	}
	wire, err := EncodeTaskCompletion(completion)
	if err != nil || !bytes.Contains(wire, []byte(`"schema_version":2`)) {
		t.Fatalf("wire: %s %v", wire, err)
	}
	parsed, err := ParseTaskCompletion(wire)
	if err != nil || parsed.Identity() != completion.Identity() {
		t.Fatalf("parse: %v", err)
	}
	state, err := coordinator.CompleteTask(ctx, plan, lease, parsed, time.UnixMilli(at+1))
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := state.Task(task.Key())
	if runtime.Status() != TaskRuntimeFailed || runtime.OutputIdentity() != output || state.OutputIdentity() != "" {
		t.Fatal("failed output became success")
	}
	if candidates, _ := state.Task("candidates"); candidates.Status() != TaskRuntimePending {
		t.Fatal("generation became available")
	}
	receipt, err := coordinator.Receipt(ctx, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	taskReceipt, _ := receipt.Task(task.Key())
	encodedReceipt, err := EncodeReviewRunReceipt(receipt)
	if err != nil || taskReceipt.OutputIdentity() != output || !bytes.Contains(encodedReceipt, []byte(`"schema_version":2`)) || !bytes.Contains(encodedReceipt, []byte(`"output_kind":"context_abstention"`)) {
		t.Fatalf("receipt: %v", err)
	}
	if _, err := ParseReviewRunReceipt(encodedReceipt); err != nil {
		t.Fatal(err)
	}
	restarted, _ := NewCoordinator(journal)
	_, replayed, err := restarted.Resume(ctx, plan.Scope())
	if err != nil || replayed.HeadIdentity() != state.HeadIdentity() {
		t.Fatalf("replay: %v", err)
	}
	events, err := readAllRunEvents(ctx, journal, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	eventWire, err := EncodeRunEvent(last)
	if err != nil || !bytes.Contains(eventWire, []byte(`"schema_version":2`)) || !bytes.Contains(eventWire, []byte(`"output_kind":"context_abstention"`)) || last.OutputIdentity() != output {
		t.Fatalf("event: %s %v", eventWire, err)
	}
	if _, err := ParseRunEvent(eventWire); err != nil {
		t.Fatal(err)
	}
	malformedEvent := bytes.Replace(eventWire, []byte(`"output_kind":"context_abstention"`), []byte(`"output_kind":"other"`), 1)
	if _, err := ParseRunEvent(malformedEvent); err == nil {
		t.Fatal("wrong event output kind accepted")
	}
	malformedReceipt := bytes.Replace(encodedReceipt, []byte(`"output_kind":"context_abstention"`), []byte(`"output_kind":"other"`), 1)
	if _, err := ParseReviewRunReceipt(malformedReceipt); err == nil {
		t.Fatal("wrong receipt output kind accepted")
	}
	malformedCompletion := bytes.Replace(wire, []byte(`"output_kind":"context_abstention"`), []byte(`"output_kind":"other"`), 1)
	if _, err := ParseTaskCompletion(malformedCompletion); err == nil {
		t.Fatal("wrong completion output kind accepted")
	}
	if _, err := restarted.CompleteTask(ctx, plan, lease, parsed, time.UnixMilli(at+2)); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
	different, _ := NewContextTaskFailureWithOutput(RunFailurePolicy, plan, task, strings.Repeat("b", 64))
	if _, err := restarted.CompleteTask(ctx, plan, lease, different, time.UnixMilli(at+2)); !errors.Is(err, ErrTaskAlreadyCompleted) {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestContextFailureOutputRejectsWrongTaskAndMalformedLinks(t *testing.T) {
	plan := runPlanFixture(t)
	task, _ := plan.Task("context")
	source, _ := plan.Task("source")
	digest := strings.Repeat("a", 64)
	if _, err := NewContextTaskFailureWithOutput(RunFailurePolicy, plan, source, digest); err == nil {
		t.Fatal("non-context accepted")
	}
	if _, err := NewContextTaskFailureWithOutput(RunFailurePolicy, plan, task, "bad"); err == nil {
		t.Fatal("bad digest accepted")
	}
	foreign := runPlanFixture(t)
	foreign.identity = strings.Repeat("f", 64)
	if _, err := NewContextTaskFailureWithOutput(RunFailurePolicy, foreign, task, digest); err == nil {
		t.Fatal("foreign plan accepted")
	}
	completion, _ := NewContextTaskFailureWithOutput(RunFailurePolicy, plan, task, digest)
	tampered := completion
	tampered.taskIdentity = source.Identity()
	if tampered.Validate() == nil {
		t.Fatal("cross-task completion accepted")
	}
	old, _ := NewTaskFailure(RunFailurePolicy)
	oldWire, _ := EncodeTaskCompletion(old)
	if !bytes.Contains(oldWire, []byte(`"schema_version":1`)) || old.OutputIdentity() != "" {
		t.Fatal("old failure changed")
	}
	event, err := NewRunEvent(plan, 2, strings.Repeat("e", 64), RunEventTaskFailed, source, 1, digest, "", time.Time{}, digest, RunFailurePolicy, time.Time{}, time.UnixMilli(300))
	if err == nil || event.Identity() != "" {
		t.Fatal("non-context event accepted")
	}
}
