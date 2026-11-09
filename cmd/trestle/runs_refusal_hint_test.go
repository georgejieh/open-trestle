package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
)

var hintShortfall = controlplane.TaskFailureContextShortfall{RequiredTokens: 14282, EstimatedInputTokens: 10186, MaxOutputTokens: 4096, DeclaredContextTokens: 4097}

const wantShortfallHint = "runs status: task context refused: route_context_insufficient (the review request needs more context than the route declares)\nhint: the review needs up to 14282 tokens (a byte-based upper bound: 10186 input plus 4096 output) but the route declares max_context_tokens 4097; raise max_context_tokens on the route and the model server's context length to at least 14282 (docs/named-local-runtimes.md#context-length)\n"

// refusedContextReceipt records a context task refused for its route.
func refusedContextReceipt(t *testing.T, reason controlplane.TaskFailureReason, shortfall controlplane.TaskFailureContextShortfall) controlplane.ReviewRunReceipt {
	t.Helper()
	ctx := context.Background()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	source, _ := controlplane.NewTaskDefinition("a-source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("e", 64), nil, 1, 0, 1000, true)
	build, _ := controlplane.NewTaskDefinition("b-build", controlplane.TaskBuildChange, strings.Repeat("a", 64), strings.Repeat("f", 64), []string{"a-source"}, 1, 0, 1000, true)
	task, err := controlplane.NewTaskDefinition("context", controlplane.TaskAssembleContext, strings.Repeat("a", 64), strings.Repeat("d", 64), []string{"b-build"}, 1, 0, 30000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{source, build, task})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	if _, err := coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	at := time.UnixMilli(101)
	for _, prerequisite := range []controlplane.TaskDefinition{source, build} {
		if _, err := coordinator.Advance(ctx, plan, at); err != nil {
			t.Fatal(err)
		}
		lease, _, err := coordinator.ClaimTask(ctx, plan, prerequisite.Key(), prerequisite.HandlerIdentity(), "worker", at)
		if err != nil {
			t.Fatal(err)
		}
		success, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
		if _, err := coordinator.CompleteTask(ctx, plan, lease, success, at); err != nil {
			t.Fatal(err)
		}
		at = at.Add(time.Millisecond)
	}
	if _, err := coordinator.Advance(ctx, plan, at); err != nil {
		t.Fatal(err)
	}
	lease, ok, err := coordinator.ClaimTask(ctx, plan, "context", task.HandlerIdentity(), "worker", at)
	if err != nil || !ok {
		t.Fatal(err)
	}
	refusal, err := controlplane.NewContextTaskRefusal(reason, shortfall, plan, task)
	if err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.CompleteTask(ctx, plan, lease, refusal, time.UnixMilli(103))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func runStatusAgainst(t *testing.T, receipt controlplane.ReviewRunReceipt, set *diagnostics.Set, format string) (int, string, string) {
	t.Helper()
	encodedReceipt, err := controlplane.EncodeReviewRunReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	runResponse, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-run", "run": json.RawMessage(encodedReceipt)})
	var diagnosticResponse []byte
	if set != nil {
		encodedSet, err := diagnostics.EncodeSet(*set)
		if err != nil {
			t.Fatal(err)
		}
		diagnosticResponse, _ = json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-diagnostics", "diagnostics": json.RawMessage(encodedSet)})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a":
			_, _ = w.Write(runResponse)
		case "/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/diagnostics":
			_, _ = w.Write(diagnosticResponse)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	var out, errs bytes.Buffer
	exit := run([]string{"runs", "status", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a", "--server", server.URL, "--format", format}, &out, &errs)
	return exit, out.String(), errs.String()
}

// runs status names a recorded context route refusal on stderr with the
// local review's hint, and keeps stdout the unchanged machine-readable result.
func TestRunStatusNamesContextRouteRefusal(t *testing.T) {
	receipt := refusedContextReceipt(t, controlplane.TaskFailureReasonRouteContextInsufficient, hintShortfall)
	exit, out, errs := runStatusAgainst(t, receipt, nil, "run")
	encoded, _ := controlplane.EncodeReviewRunReceipt(receipt)
	if exit != 0 || out != string(encoded)+"\n" || errs != wantShortfallHint {
		t.Fatalf("exit=%d stdout=%s stderr=%q", exit, out, errs)
	}
	noRoute := refusedContextReceipt(t, controlplane.TaskFailureReasonNoEligibleRoute, controlplane.TaskFailureContextShortfall{})
	if exit, _, errs := runStatusAgainst(t, noRoute, nil, "run"); exit != 0 || errs != "runs status: task context refused: no_eligible_route (no configured route met the runtime policy for this request)\n" {
		t.Fatalf("no route: exit=%d stderr=%q", exit, errs)
	}
	failed, _, _ := finalSARIFSet(t, diagnostics.FinalOutcomeFailed, true, false)
	refused, err := failed.WithContextRefusal(diagnostics.ContextRefusal{Reason: diagnostics.ContextRefusalRouteContextInsufficient, RequiredTokens: 14282, EstimatedInputTokens: 10186, MaxOutputTokens: 4096, DeclaredContextTokens: 4097})
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "sarif"} {
		if exit, out, errs := runStatusAgainst(t, receipt, &refused, format); exit != 0 || out == "" || errs != wantShortfallHint {
			t.Fatalf("%s: exit=%d stderr=%q", format, exit, errs)
		}
	}
	if exit, _, errs := runStatusAgainst(t, receipt, &failed, "json"); exit != 0 || errs != "" {
		t.Fatalf("refusal-free set: exit=%d stderr=%q", exit, errs)
	}
}
