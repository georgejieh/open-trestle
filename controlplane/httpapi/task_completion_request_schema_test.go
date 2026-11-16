package httpapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
)

// Every task completion request the daemon accepts validates against the
// published request schema, whichever completion version it carries: v1, v2
// (a context abstention), or v3 (a failure reason).
func TestTaskCompletionRequestsMatchThePublishedSchema(t *testing.T) {
	ctx := context.Background()
	schemas := publishedSchemas(t)
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	if err != nil {
		t.Fatal(err)
	}
	at := time.UnixMilli(1000)
	plan := singleAttemptPlan(t, "run-a")
	if _, err := coordinator.Open(ctx, plan, at); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Advance(ctx, plan, at); err != nil {
		t.Fatal(err)
	}
	source, _ := plan.Task("source")
	contextTask, _ := plan.Task("context")
	lease, claimed, err := coordinator.ClaimTask(ctx, plan, "source", source.HandlerIdentity(), "worker-a", at)
	if err != nil || !claimed {
		t.Fatalf("claim: %v", err)
	}
	encodedLease, err := controlplane.EncodeTaskLease(lease)
	if err != nil {
		t.Fatal(err)
	}
	success, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
	abstention, _ := controlplane.NewContextTaskFailureWithOutput(controlplane.RunFailurePolicy, plan, contextTask, strings.Repeat("f", 64))
	reasoned, _ := controlplane.NewSourceTaskFailureWithReason(controlplane.RunFailureInvalidInput, controlplane.TaskFailureReasonNoMergeBase, plan, source)
	for version, completion := range map[int]controlplane.TaskCompletion{1: success, 2: abstention, 3: reasoned} {
		encodedCompletion, err := controlplane.EncodeTaskCompletion(completion)
		if err != nil {
			t.Fatal(err)
		}
		var header struct {
			SchemaVersion int `json:"schema_version"`
		}
		if err := json.Unmarshal(encodedCompletion, &header); err != nil || header.SchemaVersion != version {
			t.Fatalf("fixture did not produce completion v%d: got v%d", version, header.SchemaVersion)
		}
		request, err := json.Marshal(taskCompletionRequestRecord{Contract: "open-trestle/task-completion-request", SchemaVersion: 1, Lease: encodedLease, Completion: encodedCompletion})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := parseTaskCompletionRequest(request); err != nil {
			t.Fatalf("the daemon refused a completion v%d request: %v", version, err)
		}
		if err := validatePublished(t, schemas, "urn:open-trestle:schema:controlplane:task-completion-request:v1", request); err != nil {
			t.Errorf("task completion request with completion v%d does not match its schema: %v", version, err)
		}
	}
}
