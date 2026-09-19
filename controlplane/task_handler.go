package controlplane

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"
)

var (
	// ErrInvalidTaskHandler identifies a missing handler implementation.
	ErrInvalidTaskHandler = errors.New("invalid review task handler")
	// ErrInvalidTaskHandlerCatalog identifies an empty, excessive, or malformed handler catalog.
	ErrInvalidTaskHandlerCatalog = errors.New("invalid review task handler catalog")
	// ErrDuplicateTaskHandler identifies competing implementations for one handler identity.
	ErrDuplicateTaskHandler = errors.New("duplicate review task handler")
	// ErrTaskHandlerNotRegistered identifies a plan handler absent from the catalog.
	ErrTaskHandlerNotRegistered = errors.New("review task handler not registered")
	// ErrTaskHandlerKindMismatch identifies an implementation for another task kind.
	ErrTaskHandlerKindMismatch = errors.New("review task handler kind mismatch")
	// ErrInvalidTaskExecutionRequest identifies cross-wired plan, task, handler, or lease lineage.
	ErrInvalidTaskExecutionRequest = errors.New("invalid task execution request")
	// ErrInvalidTaskExecutionRequestIdentity identifies request content inconsistent with its identity.
	ErrInvalidTaskExecutionRequestIdentity = errors.New("invalid task execution request identity")
	// ErrTaskDependencyOutputMismatch identifies missing, nonterminal, duplicate, or cross-wired dependency output.
	ErrTaskDependencyOutputMismatch = errors.New("task dependency output mismatch")
)

// TaskDependencyOutput binds one successful prerequisite output to its immutable plan task.
type TaskDependencyOutput struct {
	identity, planIdentity, taskKey, taskIdentity, outputIdentity string
	available                                                     bool
	failure                                                       RunFailure
}

// NewTaskDependencyOutput creates one exact prerequisite output binding.
func NewTaskDependencyOutput(plan ReviewRunPlan, taskKey, outputIdentity string) (TaskDependencyOutput, error) {
	if err := plan.Validate(); err != nil {
		return TaskDependencyOutput{}, err
	}
	task, exists := plan.Task(taskKey)
	if !exists || !validControlPlaneDigest(outputIdentity) {
		return TaskDependencyOutput{}, ErrTaskDependencyOutputMismatch
	}
	output := TaskDependencyOutput{
		planIdentity: plan.Identity(), taskKey: task.Key(), taskIdentity: task.Identity(),
		outputIdentity: outputIdentity, available: true,
	}
	output.identity = deriveTaskDependencyOutputIdentity(output)
	return output, nil
}

// NewUnavailableTaskDependencyOutput records one terminal optional prerequisite without output.
func NewUnavailableTaskDependencyOutput(plan ReviewRunPlan, taskKey string, failure RunFailure) (TaskDependencyOutput, error) {
	if err := plan.Validate(); err != nil {
		return TaskDependencyOutput{}, err
	}
	task, exists := plan.Task(taskKey)
	if !exists || task.Required() || failure.String() == "" {
		return TaskDependencyOutput{}, ErrTaskDependencyOutputMismatch
	}
	output := TaskDependencyOutput{
		planIdentity: plan.Identity(), taskKey: task.Key(), taskIdentity: task.Identity(), failure: failure,
	}
	output.identity = deriveTaskDependencyOutputIdentity(output)
	return output, nil
}

func (o TaskDependencyOutput) Identity() string       { return o.identity }
func (o TaskDependencyOutput) PlanIdentity() string   { return o.planIdentity }
func (o TaskDependencyOutput) TaskKey() string        { return o.taskKey }
func (o TaskDependencyOutput) TaskIdentity() string   { return o.taskIdentity }
func (o TaskDependencyOutput) OutputIdentity() string { return o.outputIdentity }
func (o TaskDependencyOutput) Available() bool        { return o.available }
func (o TaskDependencyOutput) Failure() RunFailure    { return o.failure }
func (o TaskDependencyOutput) String() string         { return "task dependency output" }
func (o TaskDependencyOutput) GoString() string {
	return "controlplane.TaskDependencyOutput{<redacted>}"
}
func (o TaskDependencyOutput) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "task dependency output", "controlplane.TaskDependencyOutput{<redacted>}")
}
func (o TaskDependencyOutput) Validate() error {
	if !validControlPlaneDigest(o.planIdentity) || !validReviewTaskKey(o.taskKey) ||
		!validControlPlaneDigest(o.taskIdentity) || o.identity != deriveTaskDependencyOutputIdentity(o) {
		return ErrTaskDependencyOutputMismatch
	}
	if o.available {
		if !validControlPlaneDigest(o.outputIdentity) || o.failure != 0 {
			return ErrTaskDependencyOutputMismatch
		}
	} else if o.outputIdentity != "" || o.failure.String() == "" {
		return ErrTaskDependencyOutputMismatch
	}
	return nil
}

func deriveTaskDependencyOutputIdentity(output TaskDependencyOutput) string {
	return hashControlPlaneValue(struct {
		Contract  string `json:"contract"`
		Version   int    `json:"version"`
		Plan      string `json:"plan"`
		TaskKey   string `json:"task_key"`
		Task      string `json:"task"`
		Output    string `json:"output"`
		Available bool   `json:"available"`
		Failure   string `json:"failure"`
	}{"open-trestle/task-dependency-output", 1, output.planIdentity, output.taskKey, output.taskIdentity, output.outputIdentity, output.available, output.failure.String()})
}

// TaskExecutionRequest releases only immutable identities and the exact lease to a handler.
type TaskExecutionRequest struct {
	identity          string
	plan              ReviewRunPlan
	task              TaskDefinition
	lease             TaskLease
	dependencyOutputs []TaskDependencyOutput
}

// NewTaskExecutionRequest binds an exact immutable plan, task, and live lease for remote execution.
func NewTaskExecutionRequest(plan ReviewRunPlan, task TaskDefinition, lease TaskLease) (TaskExecutionRequest, error) {
	return NewTaskExecutionRequestWithDependencies(plan, task, lease, nil)
}

// NewTaskExecutionRequestWithDependencies binds exact successful prerequisite outputs.
func NewTaskExecutionRequestWithDependencies(
	plan ReviewRunPlan,
	task TaskDefinition,
	lease TaskLease,
	outputs []TaskDependencyOutput,
) (TaskExecutionRequest, error) {
	canonical := append([]TaskDependencyOutput(nil), outputs...)
	sort.Slice(canonical, func(first, second int) bool { return canonical[first].TaskKey() < canonical[second].TaskKey() })
	request := TaskExecutionRequest{plan: plan, task: task, lease: lease, dependencyOutputs: canonical}
	request.identity = deriveTaskExecutionRequestIdentity(request)
	if err := request.Validate(); err != nil {
		return TaskExecutionRequest{}, err
	}
	return request, nil
}
func (r TaskExecutionRequest) Identity() string     { return r.identity }
func (r TaskExecutionRequest) Plan() ReviewRunPlan  { return r.plan }
func (r TaskExecutionRequest) Task() TaskDefinition { return r.task }
func (r TaskExecutionRequest) Lease() TaskLease     { return r.lease }

// DependencyOutputs returns exact prerequisite outputs in task-key order.
func (r TaskExecutionRequest) DependencyOutputs() []TaskDependencyOutput {
	return append([]TaskDependencyOutput(nil), r.dependencyOutputs...)
}

// DependencyOutput resolves one exact prerequisite task key.
func (r TaskExecutionRequest) DependencyOutput(taskKey string) (TaskDependencyOutput, bool) {
	index := sort.Search(len(r.dependencyOutputs), func(index int) bool {
		return r.dependencyOutputs[index].TaskKey() >= taskKey
	})
	if index == len(r.dependencyOutputs) || r.dependencyOutputs[index].TaskKey() != taskKey {
		return TaskDependencyOutput{}, false
	}
	return r.dependencyOutputs[index], true
}
func (r TaskExecutionRequest) String() string { return "task execution request" }
func (r TaskExecutionRequest) GoString() string {
	return "controlplane.TaskExecutionRequest{<redacted>}"
}
func (r TaskExecutionRequest) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "task execution request", "controlplane.TaskExecutionRequest{<redacted>}")
}
func (r TaskExecutionRequest) Validate() error {
	if err := r.plan.Validate(); err != nil {
		return err
	}
	if err := r.task.Validate(); err != nil {
		return err
	}
	if err := r.lease.Validate(); err != nil {
		return err
	}
	matchingPlan := r.lease.PlanIdentity() == r.plan.Identity()
	matchingTask := r.lease.TaskIdentity() == r.task.Identity() && r.lease.TaskKey() == r.task.Key()
	matchingHandler := r.lease.HandlerIdentity() == r.task.HandlerIdentity()
	if !matchingPlan || !matchingTask || !matchingHandler {
		return ErrInvalidTaskExecutionRequest
	}
	dependencies := r.task.Dependencies()
	if len(dependencies) != len(r.dependencyOutputs) {
		return ErrTaskDependencyOutputMismatch
	}
	for index, output := range r.dependencyOutputs {
		dependency, exists := r.plan.Task(dependencies[index])
		if output.Validate() != nil || !exists || output.PlanIdentity() != r.plan.Identity() ||
			output.TaskKey() != dependencies[index] || output.TaskIdentity() != dependency.Identity() {
			return ErrTaskDependencyOutputMismatch
		}
	}
	if r.identity != deriveTaskExecutionRequestIdentity(r) {
		return ErrInvalidTaskExecutionRequestIdentity
	}
	return nil
}

// TaskHandler performs one closed task kind for its exact approved identity.
type TaskHandler interface {
	HandlerIdentity() string
	Kind() TaskKind
	Execute(context.Context, TaskExecutionRequest) TaskCompletion
}

// TaskHandlerCatalog is an immutable-to-callers exact identity map.
type TaskHandlerCatalog struct{ handlers map[string]TaskHandler }

func NewTaskHandlerCatalog(handlers []TaskHandler) (TaskHandlerCatalog, error) {
	if len(handlers) == 0 || len(handlers) > maxReviewRunTasks {
		return TaskHandlerCatalog{}, ErrInvalidTaskHandlerCatalog
	}
	catalog := TaskHandlerCatalog{handlers: make(map[string]TaskHandler, len(handlers))}
	for _, handler := range handlers {
		if isNilTaskHandler(handler) {
			return TaskHandlerCatalog{}, ErrInvalidTaskHandler
		}
		identity := handler.HandlerIdentity()
		if !validControlPlaneDigest(identity) {
			return TaskHandlerCatalog{}, ErrInvalidReviewTaskHandler
		}
		if err := handler.Kind().Validate(); err != nil {
			return TaskHandlerCatalog{}, err
		}
		if _, exists := catalog.handlers[identity]; exists {
			return TaskHandlerCatalog{}, ErrDuplicateTaskHandler
		}
		catalog.handlers[identity] = handler
	}
	return catalog, nil
}
func (c TaskHandlerCatalog) Len() int { return len(c.handlers) }
func (c TaskHandlerCatalog) Resolve(identity string) (TaskHandler, bool) {
	handler, exists := c.handlers[identity]
	return handler, exists && !isNilTaskHandler(handler)
}
func (c TaskHandlerCatalog) Validate() error {
	if len(c.handlers) == 0 || len(c.handlers) > maxReviewRunTasks {
		return ErrInvalidTaskHandlerCatalog
	}
	for identity, handler := range c.handlers {
		if !validControlPlaneDigest(identity) || isNilTaskHandler(handler) || handler.HandlerIdentity() != identity || handler.Kind().Validate() != nil {
			return ErrInvalidTaskHandlerCatalog
		}
	}
	return nil
}
func (c TaskHandlerCatalog) String() string   { return "task handler catalog" }
func (c TaskHandlerCatalog) GoString() string { return "controlplane.TaskHandlerCatalog{<redacted>}" }
func (c TaskHandlerCatalog) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "task handler catalog", "controlplane.TaskHandlerCatalog{<redacted>}")
}

// DispatchLeasedTask invokes only the exact handler bound into the task and lease.
func DispatchLeasedTask(ctx context.Context, catalog TaskHandlerCatalog, state ReviewRunState, lease TaskLease, at time.Time) (TaskCompletion, error) {
	if isNilRunJournalContext(ctx) {
		return TaskCompletion{}, ErrInvalidRunJournalContext
	}
	if err := ctx.Err(); err != nil {
		return TaskCompletion{}, ErrRunJournalContextDone
	}
	if err := catalog.Validate(); err != nil {
		return TaskCompletion{}, err
	}
	if err := state.Validate(); err != nil {
		return TaskCompletion{}, err
	}
	plan := state.Plan()
	if state.Status() != ReviewRunActive {
		return TaskCompletion{}, ErrRunAlreadyTerminal
	}
	if !transitionTimeAllowed(state, at) {
		return TaskCompletion{}, ErrRunTransitionSequenceMismatch
	}
	if err := lease.Validate(); err != nil {
		return TaskCompletion{}, err
	}
	if lease.PlanIdentity() != plan.Identity() {
		return TaskCompletion{}, ErrInvalidTaskExecutionRequest
	}
	task, exists := plan.Task(lease.TaskKey())
	if !exists || task.Identity() != lease.TaskIdentity() || task.HandlerIdentity() != lease.HandlerIdentity() {
		return TaskCompletion{}, ErrInvalidTaskExecutionRequest
	}
	runtime, exists := state.Task(lease.TaskKey())
	if !exists || !runtimeMatchesLease(runtime, lease) || at.UnixMilli() > runtime.leaseExpiresAtMillis {
		return TaskCompletion{}, ErrRunTransitionLeaseMismatch
	}
	handler, exists := catalog.Resolve(task.HandlerIdentity())
	if !exists {
		return TaskCompletion{}, ErrTaskHandlerNotRegistered
	}
	if handler.Kind() != task.Kind() {
		return TaskCompletion{}, ErrTaskHandlerKindMismatch
	}
	dependencies, err := TaskDependencyOutputsFromState(state, task)
	if err != nil {
		return TaskCompletion{}, err
	}
	request, err := NewTaskExecutionRequestWithDependencies(plan, task, lease, dependencies)
	if err != nil {
		return TaskCompletion{}, err
	}
	completion := handler.Execute(ctx, request)
	if err := completion.Validate(); err != nil {
		return TaskCompletion{}, err
	}
	return completion, nil
}
func deriveTaskExecutionRequestIdentity(request TaskExecutionRequest) string {
	preimage := struct {
		Contract     string   `json:"contract"`
		Version      int      `json:"version"`
		Plan         string   `json:"plan"`
		Task         string   `json:"task"`
		Lease        string   `json:"lease"`
		Input        string   `json:"input"`
		Handler      string   `json:"handler"`
		Dependencies []string `json:"dependencies"`
	}{
		Contract: "open-trestle/task-execution-request", Version: 1,
		Plan: request.plan.Identity(), Task: request.task.Identity(), Lease: request.lease.Identity(),
		Input: request.task.InputIdentity(), Handler: request.task.HandlerIdentity(),
		Dependencies: taskDependencyOutputIdentities(request.dependencyOutputs),
	}
	return hashControlPlaneValue(preimage)
}
func taskDependencyOutputIdentities(outputs []TaskDependencyOutput) []string {
	identities := make([]string, len(outputs))
	for index, output := range outputs {
		identities[index] = output.Identity()
	}
	return identities
}

// TaskDependencyOutputsFromState snapshots successful prerequisite outputs from replayed state.
func TaskDependencyOutputsFromState(state ReviewRunState, task TaskDefinition) ([]TaskDependencyOutput, error) {
	if state.Validate() != nil || task.Validate() != nil {
		return nil, ErrTaskDependencyOutputMismatch
	}
	plan := state.Plan()
	planned, exists := plan.Task(task.Key())
	if !exists || planned.Identity() != task.Identity() {
		return nil, ErrTaskDependencyOutputMismatch
	}
	outputs := make([]TaskDependencyOutput, len(task.Dependencies()))
	for index, key := range task.Dependencies() {
		runtime, exists := state.Task(key)
		if !exists {
			return nil, ErrTaskDependencyOutputMismatch
		}
		var output TaskDependencyOutput
		var err error
		if runtime.Status() == TaskRuntimeSucceeded {
			output, err = NewTaskDependencyOutput(plan, key, runtime.OutputIdentity())
		} else {
			output, err = NewUnavailableTaskDependencyOutput(plan, key, runtime.Failure())
		}
		if err != nil {
			return nil, ErrTaskDependencyOutputMismatch
		}
		outputs[index] = output
	}
	return outputs, nil
}

// TaskDependencyOutputsFromReceipt snapshots successful prerequisite outputs from an authenticated receipt.
func TaskDependencyOutputsFromReceipt(plan ReviewRunPlan, task TaskDefinition, receipt ReviewRunReceipt) ([]TaskDependencyOutput, error) {
	if plan.Validate() != nil || task.Validate() != nil || receipt.Validate() != nil ||
		receipt.PlanIdentity() != plan.Identity() || receipt.Scope().Identity() != plan.Scope().Identity() {
		return nil, ErrTaskDependencyOutputMismatch
	}
	planned, exists := plan.Task(task.Key())
	if !exists || planned.Identity() != task.Identity() {
		return nil, ErrTaskDependencyOutputMismatch
	}
	outputs := make([]TaskDependencyOutput, len(task.Dependencies()))
	for index, key := range task.Dependencies() {
		dependencyReceipt, exists := receipt.Task(key)
		dependency, plannedDependency := plan.Task(key)
		if !exists || !plannedDependency || dependencyReceipt.TaskIdentity() != dependency.Identity() {
			return nil, ErrTaskDependencyOutputMismatch
		}
		var output TaskDependencyOutput
		var err error
		if dependencyReceipt.Status() == TaskRuntimeSucceeded {
			output, err = NewTaskDependencyOutput(plan, key, dependencyReceipt.OutputIdentity())
		} else {
			output, err = NewUnavailableTaskDependencyOutput(plan, key, dependencyReceipt.Failure())
		}
		if err != nil {
			return nil, ErrTaskDependencyOutputMismatch
		}
		outputs[index] = output
	}
	return outputs, nil
}

func isNilTaskHandler(handler TaskHandler) bool {
	if handler == nil {
		return true
	}
	value := reflect.ValueOf(handler)
	return value.Kind() == reflect.Pointer && value.IsNil()
}
