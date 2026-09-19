package artifact

import (
	"context"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"strings"
	"testing"
	"time"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }

type innerHandler struct {
	calls      int
	completion controlplane.TaskCompletion
}

func (h *innerHandler) HandlerIdentity() string     { return strings.Repeat("d", 64) }
func (h *innerHandler) Kind() controlplane.TaskKind { return controlplane.TaskAcquireSource }
func (h *innerHandler) Execute(context.Context, controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	h.calls++
	return h.completion
}
func taskRequestFixture(t *testing.T, inputIdentity string) (controlplane.ReviewRunState, controlplane.TaskLease) {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, inputIdentity, strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(101))
	lease, _, err := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker-a", time.UnixMilli(102))
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := coordinator.Resume(context.Background(), plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	return state, lease
}
func TestTaskHandlerValidatesDurableInputAndOutputArtifacts(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	store, _ := NewMemoryStore(ProtectionProcessPrivate, 10)
	input, _ := New(scope, KindTaskInput, "application/json", ClassificationConfidential, OriginHost, ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, []byte(`{}`), time.UnixMilli(1), time.UnixMilli(1000))
	output, _ := New(scope, KindChangeModel, "application/json", ClassificationConfidential, OriginDeterministicTool, ProtectionProcessPrivate, []string{input.Identity()}, []byte(`{"ok":true}`), time.UnixMilli(2), time.UnixMilli(1000))
	_, _ = store.Put(context.Background(), input, time.UnixMilli(10))
	_, _ = store.Put(context.Background(), output, time.UnixMilli(10))
	completion, _ := controlplane.NewTaskSuccess(output.Identity())
	inner := &innerHandler{completion: completion}
	handler, err := NewValidatedTaskHandler(inner, store, fixedClock{at: time.UnixMilli(200)}, []Kind{KindTaskInput}, []Kind{KindChangeModel})
	if err != nil {
		t.Fatal(err)
	}
	state, lease := taskRequestFixture(t, input.Identity())
	catalog, _ := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	result, err := controlplane.DispatchLeasedTask(context.Background(), catalog, state, lease, time.UnixMilli(200))
	if err != nil {
		t.Fatal(err)
	}
	if result.Identity() != completion.Identity() || inner.calls != 1 {
		t.Fatalf("result=%#v calls=%d", result, inner.calls)
	}
}
func TestTaskHandlerFailsClosedBeforeCallingInnerForMissingInput(t *testing.T) {
	store, _ := NewMemoryStore(ProtectionProcessPrivate, 10)
	completion, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
	inner := &innerHandler{completion: completion}
	handler, _ := NewValidatedTaskHandler(inner, store, fixedClock{at: time.UnixMilli(200)}, []Kind{KindTaskInput}, []Kind{KindChangeModel})
	state, lease := taskRequestFixture(t, strings.Repeat("a", 64))
	catalog, _ := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{handler})
	result, err := controlplane.DispatchLeasedTask(context.Background(), catalog, state, lease, time.UnixMilli(200))
	if err != nil {
		t.Fatal(err)
	}
	if result.Status() != controlplane.TaskCompletionFailed || result.Failure() != controlplane.RunFailureInternal || inner.calls != 0 {
		t.Fatalf("result=%#v calls=%d", result, inner.calls)
	}
}
