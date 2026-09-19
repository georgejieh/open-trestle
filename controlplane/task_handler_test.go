package controlplane

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type recordingTaskHandler struct {
	identity   string
	kind       TaskKind
	completion TaskCompletion
	calls      int
	request    TaskExecutionRequest
}

func (h *recordingTaskHandler) HandlerIdentity() string { return h.identity }
func (h *recordingTaskHandler) Kind() TaskKind          { return h.kind }
func (h *recordingTaskHandler) Execute(_ context.Context, request TaskExecutionRequest) TaskCompletion {
	h.calls++
	h.request = request
	return h.completion
}
func leasedTaskFixture(t *testing.T) (ReviewRunState, TaskLease) {
	t.Helper()
	journal := NewMemoryRunJournal()
	coordinator, _ := NewCoordinator(journal)
	plan := runPlanFixture(t)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(110))
	lease, acquired, err := coordinator.ClaimTask(context.Background(), plan, "source", strings.Repeat("d", 64), "worker", time.UnixMilli(200))
	if err != nil || !acquired {
		t.Fatal("lease unavailable")
	}
	_, state, err := coordinator.Resume(context.Background(), plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	return state, lease
}
func TestDispatchLeasedTaskUsesExactApprovedHandler(t *testing.T) {
	state, lease := leasedTaskFixture(t)
	completion, _ := NewTaskSuccess(strings.Repeat("e", 64))
	handler := &recordingTaskHandler{identity: strings.Repeat("d", 64), kind: TaskAcquireSource, completion: completion}
	catalog, err := NewTaskHandlerCatalog([]TaskHandler{handler})
	if err != nil {
		t.Fatal(err)
	}
	result, err := DispatchLeasedTask(context.Background(), catalog, state, lease, time.UnixMilli(300))
	if err != nil || result.Identity() != completion.Identity() || handler.calls != 1 || handler.request.Identity() == "" || handler.request.Lease().Identity() != lease.Identity() || handler.request.Validate() != nil || catalog.Validate() != nil {
		t.Fatalf("dispatch=(%#v,%v),calls=%d request=%#v", result, err, handler.calls, handler.request)
	}
}
func TestDispatchLeasedTaskRejectsMissingWrongAndMalformedHandlers(t *testing.T) {
	state, lease := leasedTaskFixture(t)
	success, _ := NewTaskSuccess(strings.Repeat("e", 64))
	for _, test := range []struct {
		name     string
		handlers []TaskHandler
		want     error
	}{{"missing", []TaskHandler{&recordingTaskHandler{identity: strings.Repeat("e", 64), kind: TaskAcquireSource, completion: success}}, ErrTaskHandlerNotRegistered}, {"kind", []TaskHandler{&recordingTaskHandler{identity: strings.Repeat("d", 64), kind: TaskBuildChange, completion: success}}, ErrTaskHandlerKindMismatch}, {"malformed", []TaskHandler{&recordingTaskHandler{identity: strings.Repeat("d", 64), kind: TaskAcquireSource}}, ErrInvalidTaskCompletion}} {
		t.Run(test.name, func(t *testing.T) {
			catalog, err := NewTaskHandlerCatalog(test.handlers)
			if err != nil {
				t.Fatal(err)
			}
			result, err := DispatchLeasedTask(context.Background(), catalog, state, lease, time.UnixMilli(300))
			if !errors.Is(err, test.want) || result.Identity() != "" {
				t.Fatalf("dispatch=(%#v,%v),want %v", result, err, test.want)
			}
		})
	}
}
func TestTaskHandlerCatalogRejectsEmptyNilAndDuplicate(t *testing.T) {
	handler := &recordingTaskHandler{identity: strings.Repeat("d", 64), kind: TaskAcquireSource}
	for _, test := range []struct {
		name     string
		handlers []TaskHandler
		want     error
	}{{"empty", nil, ErrInvalidTaskHandlerCatalog}, {"nil", []TaskHandler{nil}, ErrInvalidTaskHandler}, {"duplicate", []TaskHandler{handler, handler}, ErrDuplicateTaskHandler}} {
		t.Run(test.name, func(t *testing.T) {
			catalog, err := NewTaskHandlerCatalog(test.handlers)
			if !errors.Is(err, test.want) || catalog.Len() != 0 {
				t.Fatalf("catalog=(%#v,%v),want %v", catalog, err, test.want)
			}
		})
	}
}

func TestDispatchLeasedTaskRejectsExpiredLeaseBeforeHandler(t *testing.T) {
	state, lease := leasedTaskFixture(t)
	completion, _ := NewTaskSuccess(strings.Repeat("e", 64))
	handler := &recordingTaskHandler{identity: strings.Repeat("d", 64), kind: TaskAcquireSource, completion: completion}
	catalog, _ := NewTaskHandlerCatalog([]TaskHandler{handler})
	result, err := DispatchLeasedTask(context.Background(), catalog, state, lease, lease.ExpiresAt().Add(time.Millisecond))
	if !errors.Is(err, ErrRunTransitionLeaseMismatch) || result.Identity() != "" || handler.calls != 0 {
		t.Fatalf("expired dispatch=(%#v,%v),calls=%d", result, err, handler.calls)
	}
}

func TestNewTaskExecutionRequestBindsRemotePlanAndLease(t *testing.T) {
	state, lease := leasedTaskFixture(t)
	task, _ := state.Plan().Task(lease.TaskKey())
	request, err := NewTaskExecutionRequest(state.Plan(), task, lease)
	if err != nil || request.Validate() != nil || request.Task().Identity() != task.Identity() {
		t.Fatalf("request=(%#v,%v)", request, err)
	}
}

func leasedDependentTaskFixture(t *testing.T) (ReviewRunState, TaskLease, string) {
	t.Helper()
	journal := NewMemoryRunJournal()
	coordinator, _ := NewCoordinator(journal)
	plan := runPlanFixture(t)
	at := int64(100)
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(at))
	for _, key := range []string{"source", "change", "analysis", "memory", "context"} {
		at++
		_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(at))
		task, _ := plan.Task(key)
		at++
		lease, _, err := coordinator.ClaimTask(context.Background(), plan, key, task.HandlerIdentity(), "worker", time.UnixMilli(at))
		if err != nil {
			t.Fatal(err)
		}
		output := strings.Repeat(string('1'+rune(len(key)%8)), 64)
		completion, _ := NewTaskSuccess(output)
		at++
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, time.UnixMilli(at)); err != nil {
			t.Fatal(err)
		}
	}
	at++
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(at))
	candidate, _ := plan.Task("candidates")
	at++
	lease, _, err := coordinator.ClaimTask(context.Background(), plan, candidate.Key(), candidate.HandlerIdentity(), "worker", time.UnixMilli(at))
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := coordinator.Resume(context.Background(), plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	contextState, _ := state.Task("context")
	return state, lease, contextState.OutputIdentity()
}

func TestTaskExecutionRequestBindsExactDependencyOutputs(t *testing.T) {
	state, lease, contextOutput := leasedDependentTaskFixture(t)
	task, _ := state.Plan().Task("candidates")
	dependencies, err := TaskDependencyOutputsFromState(state, task)
	if err != nil || len(dependencies) != 1 || dependencies[0].TaskKey() != "context" || dependencies[0].OutputIdentity() != contextOutput {
		t.Fatalf("dependencies=(%#v,%v)", dependencies, err)
	}
	request, err := NewTaskExecutionRequestWithDependencies(state.Plan(), task, lease, dependencies)
	if err != nil || request.Validate() != nil || len(request.DependencyOutputs()) != 1 {
		t.Fatalf("request=(%#v,%v)", request, err)
	}
	resolved, found := request.DependencyOutput("context")
	if !found || resolved.OutputIdentity() != contextOutput {
		t.Fatalf("resolved=(%#v,%t)", resolved, found)
	}
	if missing, found := request.DependencyOutput("missing"); found || missing.Identity() != "" {
		t.Fatalf("missing dependency=(%#v,%t)", missing, found)
	}
	if missing, err := NewTaskExecutionRequest(state.Plan(), task, lease); !errors.Is(err, ErrTaskDependencyOutputMismatch) || missing.Identity() != "" {
		t.Fatalf("missing dependencies=(%#v,%v)", missing, err)
	}
	forged, _ := NewTaskDependencyOutput(state.Plan(), "source", strings.Repeat("f", 64))
	if request, err := NewTaskExecutionRequestWithDependencies(state.Plan(), task, lease, []TaskDependencyOutput{forged}); !errors.Is(err, ErrTaskDependencyOutputMismatch) || request.Identity() != "" {
		t.Fatalf("cross-wired dependencies=(%#v,%v)", request, err)
	}
}

func TestDispatchLeasedTaskSuppliesDependencyOutputs(t *testing.T) {
	state, lease, contextOutput := leasedDependentTaskFixture(t)
	completion, _ := NewTaskSuccess(strings.Repeat("e", 64))
	handler := &recordingTaskHandler{identity: lease.HandlerIdentity(), kind: TaskGenerateCandidates, completion: completion}
	catalog, _ := NewTaskHandlerCatalog([]TaskHandler{handler})
	result, err := DispatchLeasedTask(context.Background(), catalog, state, lease, time.UnixMilli(300))
	dependency, found := handler.request.DependencyOutput("context")
	if err != nil || result.Identity() != completion.Identity() || !found || dependency.OutputIdentity() != contextOutput {
		t.Fatalf("dispatch=(%#v,%v) dependency=(%#v,%t)", result, err, dependency, found)
	}
}

func TestTaskDependencyOutputsRepresentTerminalOptionalAbsence(t *testing.T) {
	tasks := runPlanTasks(t)
	for index, task := range tasks {
		if task.Key() == "memory" {
			tasks[index], _ = NewTaskDefinition(
				task.Key(), task.Kind(), task.InputIdentity(), task.HandlerIdentity(), task.Dependencies(),
				task.MaxAttempts(), task.RetryDelayMilliseconds(), task.LeaseDurationMilliseconds(), false,
			)
		}
	}
	plan, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunRequired, tasks)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := NewCoordinator(NewMemoryRunJournal())
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	at := int64(100)
	for _, key := range []string{"source", "change", "analysis", "memory"} {
		at++
		_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(at))
		task, _ := plan.Task(key)
		at++
		lease, _, claimErr := coordinator.ClaimTask(context.Background(), plan, key, task.HandlerIdentity(), "worker", time.UnixMilli(at))
		if claimErr != nil {
			t.Fatal(claimErr)
		}
		var completion TaskCompletion
		if key == "memory" {
			completion, _ = NewTaskFailure(RunFailurePolicy)
		} else {
			completion, _ = NewTaskSuccess(strings.Repeat("7", 64))
		}
		at++
		if _, err := coordinator.CompleteTask(context.Background(), plan, lease, completion, time.UnixMilli(at)); err != nil {
			t.Fatal(err)
		}
	}
	at++
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(at))
	_, state, err := coordinator.Resume(context.Background(), plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	contextTask, _ := plan.Task("context")
	outputs, err := TaskDependencyOutputsFromState(state, contextTask)
	if err != nil || len(outputs) != 2 || !outputs[0].Available() || outputs[1].Available() || outputs[1].Failure() != RunFailurePolicy || outputs[1].OutputIdentity() != "" {
		t.Fatalf("optional outputs=(%#v,%v)", outputs, err)
	}
}
