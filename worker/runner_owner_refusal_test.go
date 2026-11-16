package worker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

// ownerRefusalHandler settles its own context task within the lease.
type ownerRefusalHandler struct {
	coordinator *controlplane.Coordinator
	plan        controlplane.ReviewRunPlan
	settle      func(controlplane.ReviewRunPlan, controlplane.TaskDefinition) (controlplane.TaskCompletion, error)
}

func (*ownerRefusalHandler) HandlerIdentity() string { return strings.Repeat("d", 64) }
func (*ownerRefusalHandler) Kind() controlplane.TaskKind {
	return controlplane.TaskAssembleContext
}
func (*ownerRefusalHandler) Execute(context.Context, controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	return controlplane.TaskCompletion{}
}
func (h *ownerRefusalHandler) ExecuteAndSettle(ctx context.Context, request controlplane.TaskExecutionRequest) error {
	completion, err := h.settle(h.plan, request.Task())
	if err != nil {
		return err
	}
	_, err = h.coordinator.CompleteTask(ctx, h.plan, request.Lease(), completion, time.Now().UTC())
	return err
}

func ownerRefusalRunner(t *testing.T, settle func(controlplane.ReviewRunPlan, controlplane.TaskDefinition) (controlplane.TaskCompletion, error)) (*Runner, *controlplane.Coordinator, controlplane.ReviewRunPlan) {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "owner-route-refusal")
	handler := &ownerRefusalHandler{settle: settle}
	catalog, _ := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	task, err := controlplane.NewTaskDefinition("context", controlplane.TaskAssembleContext, strings.Repeat("a", 64), handler.HandlerIdentity(), []string{"b-build"}, 1, 0, 60000, true)
	if err != nil {
		t.Fatal(err)
	}
	source, _ := controlplane.NewTaskDefinition("a-source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("e", 64), nil, 1, 0, 1000, true)
	build, _ := controlplane.NewTaskDefinition("b-build", controlplane.TaskBuildChange, strings.Repeat("a", 64), strings.Repeat("f", 64), []string{"a-source"}, 1, 0, 1000, true)
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{source, build, task})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	handler.coordinator, handler.plan = coordinator, plan
	if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, prerequisite := range []controlplane.TaskDefinition{source, build} {
		if _, err := coordinator.Advance(context.Background(), plan, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		lease, _, err := coordinator.ClaimTask(context.Background(), plan, prerequisite.Key(), prerequisite.HandlerIdentity(), "fixture-worker", time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		success, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, success, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := coordinator.Advance(context.Background(), plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	runner, err := New(&coordinatorControl{coordinator: coordinator, plan: plan}, catalog, Options{Scope: scope, PollInterval: time.Second, RenewalInterval: time.Second, ExecutionTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return runner, coordinator, plan
}

// An owner that records a route refusal within its lease has settled the task.
func TestRunnerAcceptsOwnerRouteRefusal(t *testing.T) {
	shortfall := controlplane.TaskFailureContextShortfall{RequiredTokens: 14096, EstimatedInputTokens: 10000, MaxOutputTokens: 4096, DeclaredContextTokens: 8192}
	for name, refusal := range map[controlplane.TaskFailureReason]controlplane.TaskFailureContextShortfall{
		controlplane.TaskFailureReasonRouteContextInsufficient: shortfall,
		controlplane.TaskFailureReasonNoEligibleRoute:          {},
	} {
		runner, _, _ := ownerRefusalRunner(t, func(plan controlplane.ReviewRunPlan, task controlplane.TaskDefinition) (controlplane.TaskCompletion, error) {
			return controlplane.NewContextTaskRefusal(name, refusal, plan, task)
		})
		worked, _, err := runner.RunOnce(context.Background())
		if err != nil || !worked {
			t.Fatalf("%s: worked=%v err=%v", name, worked, err)
		}
	}
}

// A no-output policy failure without a route reason inside the lease is not a
// settlement the owner may claim.
func TestRunnerRefusesUnreasonedOwnerFailureWithinLease(t *testing.T) {
	runner, _, _ := ownerRefusalRunner(t, func(controlplane.ReviewRunPlan, controlplane.TaskDefinition) (controlplane.TaskCompletion, error) {
		return controlplane.NewTaskFailure(controlplane.RunFailurePolicy)
	})
	if _, _, err := runner.RunOnce(context.Background()); !errors.Is(err, ErrWorkerState) {
		t.Fatalf("unreasoned owner failure = %v", err)
	}
}
