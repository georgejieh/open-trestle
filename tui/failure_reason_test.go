package tui

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/testsupport"
)

// A model task's recorded provider refusal, or a provider reply the adapter
// refused, shows its reason and the local review's action, wrapped within the
// terminal width.
func TestRunShowsProviderRefusalReasonAndHint(t *testing.T) {
	ctx := context.Background()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-provider-refusal")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		reason controlplane.TaskFailureReason
		want   []string
	}{
		{controlplane.TaskFailureReasonProviderPaymentRequired, []string{
			"Reason      candidates: provider_payment_required (the provider refused the request for billing)\n",
			"Hint        add credit or a subscription to the provider account, or choose another route\n",
		}},
		{controlplane.TaskFailureReasonProviderResponseInvalid, []string{
			"Reason      candidates: provider_response_invalid (the provider answered, but its reply did not match what Open Trestle accepts, for example malformed or truncated output, an unrecognized field or an unexpected HTTP status)\n",
			"Hint        run the review again; if it repeats, choose another model or route and report it\n",
		}},
	} {
		receipt, err := testsupport.ProviderRefusalReceipt(scope, test.reason)
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		view, err := New(&fakeService{receipt: receipt, diagnosticErr: errors.New("not ready")}, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 80, Plain: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := view.Run(ctx); err != nil {
			t.Fatal(err)
		}
		rendered := output.String()
		joined := regexp.MustCompile(`\n {12,}`).ReplaceAllString(rendered, " ")
		for _, want := range test.want {
			if !strings.Contains(joined, want) {
				t.Errorf("%s: missing %q in:\n%s", test.reason, want, rendered)
			}
		}
		for _, line := range strings.Split(rendered, "\n") {
			if len([]rune(line)) > 80 {
				t.Errorf("line exceeds width: %q", line)
			}
		}
	}
}

// A refused source acquisition shows its recorded reason beside the run
// disposition, so an operator can tell no-merge-base from a transport failure.
func TestRunShowsSourceFailureReason(t *testing.T) {
	ctx := context.Background()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-reason")
	if err != nil {
		t.Fatal(err)
	}
	task, err := controlplane.NewTaskDefinition("source-base", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, 1, 100, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("c", 64), strings.Repeat("d", 64), controlplane.ReviewRunLocal, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(ctx, plan, time.UnixMilli(1000)); err != nil {
		t.Fatal(err)
	}
	lease, ok, err := coordinator.ClaimTask(ctx, plan, "source-base", task.HandlerIdentity(), "worker", time.UnixMilli(1001))
	if err != nil || !ok {
		t.Fatalf("claim: %v", err)
	}
	completion, err := controlplane.NewSourceTaskFailureWithReason(controlplane.RunFailurePolicy, controlplane.TaskFailureReasonNoMergeBase, plan, task)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, time.UnixMilli(1002)); err != nil {
		t.Fatal(err)
	}
	finalizer, err := controlplane.NewRunFinalizer(journal)
	if err != nil {
		t.Fatal(err)
	}
	state, terminal, err := finalizer.ReconcileRun(ctx, scope, time.UnixMilli(1003))
	if err != nil || !terminal {
		t.Fatalf("finalize terminal=%t: %v", terminal, err)
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	view, err := New(&fakeService{receipt: receipt, diagnosticErr: errors.New("no diagnostics")}, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 100, Plain: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Run(ctx); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	for _, want := range []string{"Disposition policy", "Reason      source-base: no_merge_base (the requested base and the head share no history)"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("missing %q in:\n%s", want, rendered)
		}
	}
}

// A context task refused for its route shows the reason, its fixed
// explanation and the local review's hint wrapped to the terminal width;
// the final result names the refusal as well.
func TestRunShowsContextRouteRefusalAndHint(t *testing.T) {
	ctx := context.Background()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-route")
	if err != nil {
		t.Fatal(err)
	}
	source, _ := controlplane.NewTaskDefinition("a-source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("e", 64), nil, 1, 0, 1000, true)
	build, _ := controlplane.NewTaskDefinition("b-build", controlplane.TaskBuildChange, strings.Repeat("a", 64), strings.Repeat("f", 64), []string{"a-source"}, 1, 0, 1000, true)
	task, err := controlplane.NewTaskDefinition("context", controlplane.TaskAssembleContext, strings.Repeat("a", 64), strings.Repeat("b", 64), []string{"b-build"}, 1, 0, 30000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("c", 64), strings.Repeat("d", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{source, build, task})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	if _, err := coordinator.Open(ctx, plan, time.UnixMilli(1000)); err != nil {
		t.Fatal(err)
	}
	at := time.UnixMilli(1001)
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
		t.Fatalf("claim: %v", err)
	}
	refusal, err := controlplane.NewContextTaskRefusal(controlplane.TaskFailureReasonRouteContextInsufficient, controlplane.TaskFailureContextShortfall{RequiredTokens: 14282, EstimatedInputTokens: 10186, MaxOutputTokens: 4096, DeclaredContextTokens: 4097}, plan, task)
	if err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.CompleteTask(ctx, plan, lease, refusal, at)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := diagnostics.NewFinalReviewSet(scope, "", "", diagnostics.FinalOutcomeFailed, diagnostics.Set{}, diagnostics.Set{})
	if err != nil {
		t.Fatal(err)
	}
	set, err := failed.WithContextRefusal(diagnostics.ContextRefusal{Reason: diagnostics.ContextRefusalRouteContextInsufficient, RequiredTokens: 14282, EstimatedInputTokens: 10186, MaxOutputTokens: 4096, DeclaredContextTokens: 4097})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	view, err := New(&fakeService{receipt: receipt, set: set}, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 80, Plain: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Run(ctx); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	// Wrapped lines continue under their label; join them to read each value.
	joined := regexp.MustCompile(`\n {12,}`).ReplaceAllString(rendered, " ")
	for _, want := range []string{
		"Reason      context: route_context_insufficient (the review request needs more context than the route declares)\n",
		"Hint        the review needs up to 14282 tokens (a byte-based upper bound: 10186 input plus 4096 output) but the route declares max_context_tokens 4097; raise max_context_tokens on the route and the model server's context length to at least 14282 (docs/named-local-runtimes.md#context-length)\n",
		"Context refusal: route_context_insufficient (the review request needs more context than the route declares)\n",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, rendered)
		}
	}
	for _, line := range strings.Split(rendered, "\n") {
		if len([]rune(line)) > 80 {
			t.Errorf("line exceeds width: %q", line)
		}
	}
}

// A final result recorded after its evidence expired says so.
func TestRunShowsEvidenceExpiredResult(t *testing.T) {
	ctx := context.Background()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-expired-evidence")
	if err != nil {
		t.Fatal(err)
	}
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, 1, 100, 1000, true)
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("c", 64), strings.Repeat("d", 64), controlplane.ReviewRunLocal, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	state, err := coordinator.Open(ctx, plan, time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	bare, err := diagnostics.NewFinalReviewSet(scope, "", "", diagnostics.FinalOutcomeInconclusive, diagnostics.Set{}, diagnostics.Set{})
	if err != nil {
		t.Fatal(err)
	}
	set, err := bare.WithEvidenceExpired()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	view, err := New(&fakeService{receipt: receipt, set: set}, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 80, Plain: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Run(ctx); err != nil {
		t.Fatal(err)
	}
	joined := regexp.MustCompile(`\n(?: {12,})?`).ReplaceAllString(output.String(), " ")
	if !strings.Contains(joined, diagnostics.EvidenceExpiredText) {
		t.Errorf("missing expired-evidence text in:\n%s", output.String())
	}
}
