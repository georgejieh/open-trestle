package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

// singleAttemptPlan is apiPlan's task graph in one run scope, with one
// attempt per task so a failure is terminal.
func singleAttemptPlan(t *testing.T, run string) controlplane.ReviewRunPlan {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", run)
	if err != nil {
		t.Fatal(err)
	}
	specs := []struct {
		key          string
		kind         controlplane.TaskKind
		dependencies []string
	}{{"source", controlplane.TaskAcquireSource, nil}, {"change", controlplane.TaskBuildChange, []string{"source"}}, {"analysis", controlplane.TaskInspectDeterministic, []string{"change"}}, {"memory", controlplane.TaskRetrieveContext, []string{"change"}}, {"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}}}
	tasks := make([]controlplane.TaskDefinition, 0, len(specs))
	for _, spec := range specs {
		task, err := controlplane.NewTaskDefinition(spec.key, spec.kind, strings.Repeat("a", 64), strings.Repeat("d", 64), spec.dependencies, 1, 1000, 30000, true)
		if err != nil {
			t.Fatal(err)
		}
		tasks = append(tasks, task)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, tasks)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func completeTask(t *testing.T, coordinator *controlplane.Coordinator, plan controlplane.ReviewRunPlan, key string, completion func(controlplane.TaskDefinition) (controlplane.TaskCompletion, error), at time.Time) {
	t.Helper()
	ctx := context.Background()
	task, _ := plan.Task(key)
	lease, claimed, err := coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker-a", at)
	if err != nil || !claimed {
		t.Fatalf("claim %s: claimed=%t err=%v", key, claimed, err)
	}
	result, err := completion(task)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.CompleteTask(ctx, plan, lease, result, at); err != nil {
		t.Fatalf("complete %s: %v", key, err)
	}
}

// Every GET run response the daemon writes validates against the published
// api-response schema, whichever receipt version it embeds: v1, v2 (a
// context abstention), or v3 (a failed run with a failure_reason).
func TestGetRunResponsesMatchThePublishedSchema(t *testing.T) {
	ctx := context.Background()
	schemas := publishedSchemas(t)
	server, _ := apiServer(t)
	coordinator := server.coordinator
	at := time.UnixMilli(1000)
	succeed := func(controlplane.TaskDefinition) (controlplane.TaskCompletion, error) {
		return controlplane.NewTaskSuccess(strings.Repeat("e", 64))
	}
	runs := map[int]controlplane.ReviewRunPlan{1: singleAttemptPlan(t, "run-v1"), 2: singleAttemptPlan(t, "run-v2"), 3: singleAttemptPlan(t, "run-v3")}
	for _, plan := range runs {
		if _, err := coordinator.Open(ctx, plan, at); err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.Advance(ctx, plan, at); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"source", "change", "analysis", "memory"} {
		completeTask(t, coordinator, runs[2], key, succeed, at)
		if _, err := coordinator.Advance(ctx, runs[2], at); err != nil {
			t.Fatal(err)
		}
	}
	completeTask(t, coordinator, runs[2], "context", func(task controlplane.TaskDefinition) (controlplane.TaskCompletion, error) {
		return controlplane.NewContextTaskFailureWithOutput(controlplane.RunFailurePolicy, runs[2], task, strings.Repeat("f", 64))
	}, at)
	completeTask(t, coordinator, runs[3], "source", func(task controlplane.TaskDefinition) (controlplane.TaskCompletion, error) {
		return controlplane.NewSourceTaskFailureWithReason(controlplane.RunFailureInvalidInput, controlplane.TaskFailureReasonNoMergeBase, runs[3], task)
	}, at)
	// The failed required task fails its run, as the run finalizer records it.
	for _, version := range []int{2, 3} {
		state, err := coordinator.Advance(ctx, runs[version], at)
		if err != nil {
			t.Fatal(err)
		}
		terminal, ready, err := state.TerminalCompletion()
		if err != nil || !ready {
			t.Fatalf("run v%d is not ready to settle: %v", version, err)
		}
		if _, err := coordinator.FailRun(ctx, runs[version], terminal.Failure(), at); err != nil {
			t.Fatal(err)
		}
	}
	for version, plan := range runs {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, authenticatedRequest(http.MethodGet, "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/"+plan.Scope().ReviewRunID(), nil))
		if response.Code != http.StatusOK {
			t.Fatalf("receipt v%d status=%d body=%s", version, response.Code, response.Body.String())
		}
		var envelope struct {
			Run struct {
				SchemaVersion int    `json:"schema_version"`
				Status        string `json:"status"`
				Tasks         []struct {
					FailureReason string `json:"failure_reason"`
				} `json:"tasks"`
			} `json:"run"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Run.SchemaVersion != version {
			t.Fatalf("fixture did not produce receipt v%d: got v%d err=%v", version, envelope.Run.SchemaVersion, err)
		}
		if version == 3 && (envelope.Run.Status != "failed" || !strings.Contains(response.Body.String(), `"failure_reason":"no_merge_base"`)) {
			t.Fatalf("receipt v3 fixture is not a failed run with a failure reason: %s", response.Body.String())
		}
		if err := validatePublished(t, schemas, "urn:open-trestle:schema:controlplane:api-response:v1", response.Body.Bytes()); err != nil {
			t.Errorf("GET run response with receipt v%d does not match api-response v1: %v", version, err)
		}
		if version == 3 {
			forged := strings.Replace(response.Body.String(), `"failure_reason":"no_merge_base"`, `"failure_reason":"not_a_reason"`, 1)
			if err := validatePublished(t, schemas, "urn:open-trestle:schema:controlplane:api-response:v1", []byte(forged)); err == nil {
				t.Error("the schema check accepted an unknown failure reason")
			}
		}
	}
}
