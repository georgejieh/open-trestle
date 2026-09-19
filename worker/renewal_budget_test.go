package worker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

type renewalBudgetError struct{}

func (renewalBudgetError) Error() string   { return "lease renewal limit" }
func (renewalBudgetError) StatusCode() int { return 409 }
func (renewalBudgetError) Code() string    { return "lease_renewal_limit" }

type budgetLimitedControl struct{ *coordinatorControl }

func (budgetLimitedControl) RenewTaskLease(context.Context, audit.ReviewScope, controlplane.TaskLease) (controlplane.TaskLease, error) {
	return controlplane.TaskLease{}, renewalBudgetError{}
}

func TestRunnerSettlesResourceFailureWhenRenewalBudgetIsRefused(t *testing.T) {
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-budget")
	if err != nil {
		t.Fatal(err)
	}
	handler := delayedHandler{identity: strings.Repeat("d", 64), delay: time.Second}
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), handler.identity, nil, 1, 0, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	if err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Advance(context.Background(), plan, state.LastOccurredAt().Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	control := budgetLimitedControl{&coordinatorControl{coordinator: coordinator, plan: plan}}
	catalog, err := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	if err != nil {
		t.Fatal(err)
	}
	runner, err := New(control, catalog, Options{Scope: scope, PollInterval: time.Second, RenewalInterval: 10 * time.Millisecond, ExecutionTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	worked, settled, err := runner.RunOnce(context.Background())
	if err != nil || !worked || !settled {
		t.Fatalf("renewal budget stopped worker instead of settling task: worked=%t settled=%t err=%v", worked, settled, err)
	}
	receipt, err := coordinator.Receipt(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	failed, found := receipt.Task("source")
	if !found || failed.Status() != controlplane.TaskRuntimeFailed || failed.Failure() != controlplane.RunFailureResourceLimit {
		t.Fatalf("wrong bounded failure: %#v", failed)
	}
}
