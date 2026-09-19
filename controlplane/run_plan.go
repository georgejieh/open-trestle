package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	maxReviewRunTasks               = 64
	maxReviewTaskDependencies       = 16
	maxReviewTaskKeyBytes           = 64
	maxReviewTaskAttempts     uint8 = 5
	minReviewTaskLeaseMillis        = 1_000
	maxReviewTaskLeaseMillis        = 3_600_000
)

var (
	// ErrInvalidReviewRunMode identifies an unknown review effect posture.
	ErrInvalidReviewRunMode = errors.New("invalid review run mode")
	// ErrInvalidReviewRunIdentity identifies plan content inconsistent with its identity.
	ErrInvalidReviewRunIdentity = errors.New("invalid review run plan identity")
	// ErrInvalidReviewRunRequest identifies a malformed canonical request identity.
	ErrInvalidReviewRunRequest = errors.New("invalid review run request")
	// ErrInvalidReviewRunPolicy identifies a malformed policy identity.
	ErrInvalidReviewRunPolicy = errors.New("invalid review run policy")
	// ErrInvalidReviewRunTaskCount identifies an empty or excessive task graph.
	ErrInvalidReviewRunTaskCount = errors.New("invalid review run task count")
	// ErrDuplicateReviewRunTask identifies repeated task keys.
	ErrDuplicateReviewRunTask = errors.New("duplicate review run task")
	// ErrReviewRunTaskDependencyMissing identifies a dependency outside the graph.
	ErrReviewRunTaskDependencyMissing = errors.New("review run task dependency missing")
	// ErrReviewRunTaskCycle identifies a cyclic task graph.
	ErrReviewRunTaskCycle = errors.New("review run task cycle")
	// ErrReviewRunSafetyDependencyMissing identifies a task that bypasses a required predecessor.
	ErrReviewRunSafetyDependencyMissing = errors.New("review run safety dependency missing")
	// ErrReviewRunPublicationNotAllowed identifies external publication in local-only mode.
	ErrReviewRunPublicationNotAllowed = errors.New("review run publication not allowed")
	// ErrInvalidReviewTaskKey identifies a noncanonical task key.
	ErrInvalidReviewTaskKey = errors.New("invalid review task key")
	// ErrInvalidReviewTaskKind identifies an unknown runtime operation.
	ErrInvalidReviewTaskKind = errors.New("invalid review task kind")
	// ErrInvalidReviewTaskInput identifies a malformed immutable input identity.
	ErrInvalidReviewTaskInput = errors.New("invalid review task input")
	// ErrInvalidReviewTaskHandler identifies a malformed approved handler identity.
	ErrInvalidReviewTaskHandler = errors.New("invalid review task handler")
	// ErrInvalidReviewTaskAttempts identifies an unusable retry bound.
	ErrInvalidReviewTaskAttempts = errors.New("invalid review task attempts")
	// ErrInvalidReviewTaskRetry identifies an excessive retry delay.
	ErrInvalidReviewTaskRetry = errors.New("invalid review task retry")
	// ErrInvalidReviewTaskLease identifies an unusable worker lease duration.
	ErrInvalidReviewTaskLease = errors.New("invalid review task lease")
	// ErrReviewRunTaskSelfDependency identifies direct task recursion.
	ErrReviewRunTaskSelfDependency = errors.New("review task depends on itself")
	// ErrDuplicateReviewTaskDependency identifies a repeated task dependency.
	ErrDuplicateReviewTaskDependency = errors.New("duplicate review task dependency")
	// ErrInvalidReviewTaskIdentity identifies task content inconsistent with its identity.
	ErrInvalidReviewTaskIdentity = errors.New("invalid review task identity")
	// ErrReviewRunResultTaskAmbiguous identifies a plan without one deterministic required result task.
	ErrReviewRunResultTaskAmbiguous = errors.New("review run result task ambiguous")
)

// ReviewRunMode is the maximum effect posture for one review.
type ReviewRunMode uint8

const (
	ReviewRunLocal ReviewRunMode = iota + 1
	ReviewRunAdvisory
	ReviewRunRequired
)

func (m ReviewRunMode) String() string {
	switch m {
	case ReviewRunLocal:
		return "local"
	case ReviewRunAdvisory:
		return "advisory"
	case ReviewRunRequired:
		return "required"
	default:
		return ""
	}
}
func (m ReviewRunMode) Validate() error {
	if m.String() == "" {
		return ErrInvalidReviewRunMode
	}
	return nil
}

// TaskKind identifies one bounded runtime operation.
type TaskKind uint8

const (
	TaskAcquireSource TaskKind = iota + 1
	TaskBuildChange
	TaskInspectDeterministic
	TaskRetrieveContext
	TaskAssembleContext
	TaskGenerateCandidates
	TaskVerifyCandidates
	TaskEvaluatePublication
	TaskPublishResult
)

func (k TaskKind) String() string {
	switch k {
	case TaskAcquireSource:
		return "acquire_source"
	case TaskBuildChange:
		return "build_change"
	case TaskInspectDeterministic:
		return "inspect_deterministic"
	case TaskRetrieveContext:
		return "retrieve_context"
	case TaskAssembleContext:
		return "assemble_context"
	case TaskGenerateCandidates:
		return "generate_candidates"
	case TaskVerifyCandidates:
		return "verify_candidates"
	case TaskEvaluatePublication:
		return "evaluate_publication"
	case TaskPublishResult:
		return "publish_result"
	default:
		return ""
	}
}
func (k TaskKind) Validate() error {
	if k.String() == "" {
		return ErrInvalidReviewTaskKind
	}
	return nil
}

// TaskDefinition describes one bounded, dependency-aware unit of work.
type TaskDefinition struct {
	identity            string
	key                 string
	kind                TaskKind
	inputIdentity       string
	handlerIdentity     string
	dependencies        []string
	maxAttempts         uint8
	retryDelayMillis    uint32
	leaseDurationMillis uint32
	required            bool
}

// NewTaskDefinition creates an immutable task definition.
func NewTaskDefinition(
	key string,
	kind TaskKind,
	inputIdentity string,
	handlerIdentity string,
	dependencies []string,
	maxAttempts uint8,
	retryDelayMillis uint32,
	leaseDurationMillis uint32,
	required bool,
) (TaskDefinition, error) {
	if !validReviewTaskKey(key) {
		return TaskDefinition{}, ErrInvalidReviewTaskKey
	}
	if err := kind.Validate(); err != nil {
		return TaskDefinition{}, err
	}
	if !validControlPlaneDigest(inputIdentity) {
		return TaskDefinition{}, ErrInvalidReviewTaskInput
	}
	if !validControlPlaneDigest(handlerIdentity) {
		return TaskDefinition{}, ErrInvalidReviewTaskHandler
	}
	if maxAttempts == 0 || maxAttempts > maxReviewTaskAttempts {
		return TaskDefinition{}, ErrInvalidReviewTaskAttempts
	}
	if retryDelayMillis > maxReviewTaskLeaseMillis {
		return TaskDefinition{}, ErrInvalidReviewTaskRetry
	}
	if leaseDurationMillis < minReviewTaskLeaseMillis || leaseDurationMillis > maxReviewTaskLeaseMillis {
		return TaskDefinition{}, ErrInvalidReviewTaskLease
	}
	canonicalDependencies, err := canonicalReviewTaskDependencies(key, dependencies)
	if err != nil {
		return TaskDefinition{}, err
	}
	task := TaskDefinition{
		key: strings.Clone(key), kind: kind, inputIdentity: inputIdentity, handlerIdentity: handlerIdentity,
		dependencies: canonicalDependencies, maxAttempts: maxAttempts,
		retryDelayMillis: retryDelayMillis, leaseDurationMillis: leaseDurationMillis, required: required,
	}
	task.identity = deriveTaskDefinitionIdentity(task)
	return task, nil
}

func canonicalReviewTaskDependencies(key string, dependencies []string) ([]string, error) {
	if len(dependencies) > maxReviewTaskDependencies {
		return nil, ErrReviewRunTaskDependencyMissing
	}
	canonical := append([]string(nil), dependencies...)
	sort.Strings(canonical)
	for index, dependency := range canonical {
		if !validReviewTaskKey(dependency) {
			return nil, ErrInvalidReviewTaskKey
		}
		if dependency == key {
			return nil, ErrReviewRunTaskSelfDependency
		}
		if index > 0 && canonical[index-1] == dependency {
			return nil, ErrDuplicateReviewTaskDependency
		}
	}
	if len(canonical) == 0 {
		canonical = nil
	}
	return canonical, nil
}

func (t TaskDefinition) Identity() string                  { return t.identity }
func (t TaskDefinition) Key() string                       { return t.key }
func (t TaskDefinition) Kind() TaskKind                    { return t.kind }
func (t TaskDefinition) InputIdentity() string             { return t.inputIdentity }
func (t TaskDefinition) HandlerIdentity() string           { return t.handlerIdentity }
func (t TaskDefinition) MaxAttempts() uint8                { return t.maxAttempts }
func (t TaskDefinition) RetryDelayMilliseconds() uint32    { return t.retryDelayMillis }
func (t TaskDefinition) LeaseDurationMilliseconds() uint32 { return t.leaseDurationMillis }
func (t TaskDefinition) Required() bool                    { return t.required }
func (t TaskDefinition) Dependencies() []string            { return append([]string(nil), t.dependencies...) }
func (t TaskDefinition) String() string                    { return "review task definition" }
func (t TaskDefinition) GoString() string                  { return "controlplane.TaskDefinition{<redacted>}" }
func (t TaskDefinition) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "review task definition", "controlplane.TaskDefinition{<redacted>}")
}
func (t TaskDefinition) Validate() error {
	rebuilt, err := NewTaskDefinition(t.key, t.kind, t.inputIdentity, t.handlerIdentity, t.dependencies, t.maxAttempts, t.retryDelayMillis, t.leaseDurationMillis, t.required)
	if err != nil {
		return err
	}
	if rebuilt.identity != t.identity || !slices.Equal(rebuilt.dependencies, t.dependencies) {
		return ErrInvalidReviewTaskIdentity
	}
	return nil
}

// ReviewRunPlan is the immutable task graph shared by all transports.
type ReviewRunPlan struct {
	identity        string
	scope           audit.ReviewScope
	requestIdentity string
	policyIdentity  string
	mode            ReviewRunMode
	tasks           []TaskDefinition
}

// NewReviewRunPlan validates and canonicalizes one bounded acyclic task graph.
func NewReviewRunPlan(scope audit.ReviewScope, requestIdentity, policyIdentity string, mode ReviewRunMode, tasks []TaskDefinition) (ReviewRunPlan, error) {
	if err := scope.Validate(); err != nil {
		return ReviewRunPlan{}, err
	}
	if !validControlPlaneDigest(requestIdentity) {
		return ReviewRunPlan{}, ErrInvalidReviewRunRequest
	}
	if !validControlPlaneDigest(policyIdentity) {
		return ReviewRunPlan{}, ErrInvalidReviewRunPolicy
	}
	if err := mode.Validate(); err != nil {
		return ReviewRunPlan{}, err
	}
	if len(tasks) == 0 || len(tasks) > maxReviewRunTasks {
		return ReviewRunPlan{}, ErrInvalidReviewRunTaskCount
	}
	canonicalTasks := append([]TaskDefinition(nil), tasks...)
	for _, task := range canonicalTasks {
		if err := task.Validate(); err != nil {
			return ReviewRunPlan{}, err
		}
	}
	sort.Slice(canonicalTasks, func(i, j int) bool { return canonicalTasks[i].Key() < canonicalTasks[j].Key() })
	for index := 1; index < len(canonicalTasks); index++ {
		if canonicalTasks[index-1].Key() == canonicalTasks[index].Key() {
			return ReviewRunPlan{}, ErrDuplicateReviewRunTask
		}
	}
	if err := validateReviewRunGraph(mode, canonicalTasks); err != nil {
		return ReviewRunPlan{}, err
	}
	plan := ReviewRunPlan{scope: scope, requestIdentity: requestIdentity, policyIdentity: policyIdentity, mode: mode, tasks: canonicalTasks}
	plan.identity = deriveReviewRunPlanIdentity(plan)
	return plan, nil
}

func validateReviewRunGraph(mode ReviewRunMode, tasks []TaskDefinition) error {
	byKey := make(map[string]TaskDefinition, len(tasks))
	for _, task := range tasks {
		byKey[task.Key()] = task
	}
	for _, task := range tasks {
		for _, dependency := range task.dependencies {
			if _, exists := byKey[dependency]; !exists {
				return ErrReviewRunTaskDependencyMissing
			}
		}
	}
	visiting := make(map[string]bool, len(tasks))
	visited := make(map[string]bool, len(tasks))
	var visit func(string) error
	visit = func(key string) error {
		if visiting[key] {
			return ErrReviewRunTaskCycle
		}
		if visited[key] {
			return nil
		}
		visiting[key] = true
		for _, dependency := range byKey[key].dependencies {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		visiting[key] = false
		visited[key] = true
		return nil
	}
	for _, task := range tasks {
		if err := visit(task.Key()); err != nil {
			return err
		}
	}
	return validateReviewRunSafety(mode, tasks, byKey)
}

func validateReviewRunSafety(mode ReviewRunMode, tasks []TaskDefinition, byKey map[string]TaskDefinition) error {
	kindCounts := make(map[TaskKind]int)
	for _, task := range tasks {
		kindCounts[task.Kind()]++
	}
	if kindCounts[TaskAcquireSource] == 0 {
		return ErrReviewRunSafetyDependencyMissing
	}
	if kindCounts[TaskPublishResult] > 1 || kindCounts[TaskEvaluatePublication] > 1 {
		return ErrReviewRunSafetyDependencyMissing
	}
	if mode != ReviewRunRequired && kindCounts[TaskPublishResult] != 0 {
		return ErrReviewRunPublicationNotAllowed
	}
	requiredAncestor := map[TaskKind]TaskKind{
		TaskBuildChange:          TaskAcquireSource,
		TaskInspectDeterministic: TaskBuildChange,
		TaskRetrieveContext:      TaskBuildChange,
		TaskAssembleContext:      TaskBuildChange,
		TaskGenerateCandidates:   TaskAssembleContext,
		TaskVerifyCandidates:     TaskGenerateCandidates,
		TaskEvaluatePublication:  TaskVerifyCandidates,
		TaskPublishResult:        TaskEvaluatePublication,
	}
	for _, task := range tasks {
		safetyCritical := task.Kind() != TaskInspectDeterministic && task.Kind() != TaskRetrieveContext
		if safetyCritical && !task.Required() {
			return ErrReviewRunSafetyDependencyMissing
		}
		if task.Kind() == TaskPublishResult && task.MaxAttempts() != 1 {
			return ErrReviewRunSafetyDependencyMissing
		}
		if task.Kind() == TaskAcquireSource && len(task.dependencies) != 0 {
			return ErrReviewRunSafetyDependencyMissing
		}
		ancestorKind, constrained := requiredAncestor[task.Kind()]
		if constrained && !taskHasAncestorKind(task, ancestorKind, byKey, make(map[string]bool)) {
			return ErrReviewRunSafetyDependencyMissing
		}
	}
	if _, err := resultTaskFromDefinitions(tasks); err != nil {
		return err
	}
	return nil
}

func resultTaskFromDefinitions(tasks []TaskDefinition) (TaskDefinition, error) {
	var selected TaskDefinition
	highest := TaskKind(0)
	count := 0
	for _, task := range tasks {
		if !task.Required() {
			continue
		}
		if task.Kind() > highest {
			selected, highest, count = task, task.Kind(), 1
		} else if task.Kind() == highest {
			count++
		}
	}
	if count != 1 || selected.Validate() != nil {
		return TaskDefinition{}, ErrReviewRunResultTaskAmbiguous
	}
	return selected, nil
}

func taskHasAncestorKind(task TaskDefinition, kind TaskKind, byKey map[string]TaskDefinition, seen map[string]bool) bool {
	for _, dependency := range task.dependencies {
		if seen[dependency] {
			continue
		}
		seen[dependency] = true
		parent := byKey[dependency]
		if parent.Kind() == kind || taskHasAncestorKind(parent, kind, byKey, seen) {
			return true
		}
	}
	return false
}

func (p ReviewRunPlan) Identity() string         { return p.identity }
func (p ReviewRunPlan) Scope() audit.ReviewScope { return p.scope }
func (p ReviewRunPlan) RequestIdentity() string  { return p.requestIdentity }
func (p ReviewRunPlan) PolicyIdentity() string   { return p.policyIdentity }
func (p ReviewRunPlan) Mode() ReviewRunMode      { return p.mode }
func (p ReviewRunPlan) TaskCount() int           { return len(p.tasks) }
func (p ReviewRunPlan) Tasks() []TaskDefinition  { return append([]TaskDefinition(nil), p.tasks...) }
func (p ReviewRunPlan) Task(key string) (TaskDefinition, bool) {
	index := sort.Search(len(p.tasks), func(i int) bool { return p.tasks[i].Key() >= key })
	if index == len(p.tasks) || p.tasks[index].Key() != key {
		return TaskDefinition{}, false
	}
	return p.tasks[index], true
}

// ResultTask returns the unique highest-stage required task whose output represents success.
func (p ReviewRunPlan) ResultTask() (TaskDefinition, error) {
	if p.Validate() != nil {
		return TaskDefinition{}, ErrReviewRunResultTaskAmbiguous
	}
	return resultTaskFromDefinitions(p.tasks)
}

func (p ReviewRunPlan) String() string   { return "review run plan" }
func (p ReviewRunPlan) GoString() string { return "controlplane.ReviewRunPlan{<redacted>}" }
func (p ReviewRunPlan) Format(state fmt.State, verb rune) {
	writeRedactedControlPlaneFormat(state, verb, "review run plan", "controlplane.ReviewRunPlan{<redacted>}")
}
func (p ReviewRunPlan) Validate() error {
	rebuilt, err := NewReviewRunPlan(p.scope, p.requestIdentity, p.policyIdentity, p.mode, p.tasks)
	if err != nil {
		return err
	}
	if rebuilt.identity != p.identity {
		return ErrInvalidReviewRunIdentity
	}
	return nil
}

func deriveTaskDefinitionIdentity(task TaskDefinition) string {
	preimage := struct {
		Contract          string   `json:"contract"`
		Version           int      `json:"version"`
		Key               string   `json:"key"`
		Kind              string   `json:"kind"`
		Input             string   `json:"input"`
		Handler           string   `json:"handler"`
		Dependencies      []string `json:"dependencies"`
		MaxAttempts       uint8    `json:"max_attempts"`
		RetryMilliseconds uint32   `json:"retry_milliseconds"`
		LeaseMilliseconds uint32   `json:"lease_milliseconds"`
		Required          bool     `json:"required"`
	}{
		Contract: "open-trestle/review-task-definition", Version: 1,
		Key: task.key, Kind: task.kind.String(), Input: task.inputIdentity,
		Handler: task.handlerIdentity, Dependencies: task.dependencies,
		MaxAttempts: task.maxAttempts, RetryMilliseconds: task.retryDelayMillis,
		LeaseMilliseconds: task.leaseDurationMillis, Required: task.required,
	}
	return hashControlPlaneValue(preimage)
}
func deriveReviewRunPlanIdentity(plan ReviewRunPlan) string {
	taskIdentities := make([]string, len(plan.tasks))
	for index, task := range plan.tasks {
		taskIdentities[index] = task.Identity()
	}
	preimage := struct {
		Contract string   `json:"contract"`
		Version  int      `json:"version"`
		Scope    string   `json:"scope"`
		Request  string   `json:"request"`
		Policy   string   `json:"policy"`
		Mode     string   `json:"mode"`
		Tasks    []string `json:"tasks"`
	}{"open-trestle/review-run-plan", 1, plan.scope.Identity(), plan.requestIdentity, plan.policyIdentity, plan.mode.String(), taskIdentities}
	return hashControlPlaneValue(preimage)
}
func hashControlPlaneValue(value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// ValidateTaskKey verifies a canonical task identifier.
func ValidateTaskKey(value string) error {
	if !validReviewTaskKey(value) {
		return ErrInvalidReviewTaskKey
	}
	return nil
}

// ValidateHandlerIdentity verifies a content-addressed approved handler identity.
func ValidateHandlerIdentity(value string) error {
	if !validControlPlaneDigest(value) {
		return ErrInvalidReviewTaskHandler
	}
	return nil
}

func validControlPlaneDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) || strings.Trim(value, "0") == "" {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
func validReviewTaskKey(value string) bool {
	if len(value) == 0 || len(value) > maxReviewTaskKeyBytes {
		return false
	}
	for index, candidate := range []byte(value) {
		letter := candidate >= 'a' && candidate <= 'z'
		digit := candidate >= '0' && candidate <= '9'
		separator := candidate == '.' || candidate == '_' || candidate == '-'
		if !letter && !digit && !(separator && index > 0) {
			return false
		}
	}
	last := value[len(value)-1]
	return last != '.' && last != '_' && last != '-'
}
func writeRedactedControlPlaneFormat(state fmt.State, verb rune, plain, goValue string) {
	formatted := plain
	if verb == 'q' {
		encoded, _ := json.Marshal(plain)
		formatted = string(encoded)
	} else if verb == 'v' && state.Flag('#') {
		formatted = goValue
	}
	_, _ = state.Write([]byte(formatted))
}
