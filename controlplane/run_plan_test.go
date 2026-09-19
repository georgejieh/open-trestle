package controlplane

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
)

func runScopeFixture(t *testing.T) audit.ReviewScope {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant", "repository", "run-1")
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
func taskFixture(t *testing.T, key string, kind TaskKind, dependencies ...string) TaskDefinition {
	t.Helper()
	task, err := NewTaskDefinition(key, kind, strings.Repeat("a", 64), strings.Repeat("d", 64), dependencies, 3, 1_000, 30_000, true)
	if err != nil {
		t.Fatal(err)
	}
	return task
}
func mustTaskWithAttempts(t *testing.T, key string, kind TaskKind, attempts uint8, dependencies ...string) TaskDefinition {
	t.Helper()
	task, err := NewTaskDefinition(key, kind, strings.Repeat("a", 64), strings.Repeat("d", 64), dependencies, attempts, 1_000, 30_000, true)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func runPlanTasks(t *testing.T) []TaskDefinition {
	t.Helper()
	return []TaskDefinition{
		taskFixture(t, "source", TaskAcquireSource),
		taskFixture(t, "change", TaskBuildChange, "source"),
		taskFixture(t, "analysis", TaskInspectDeterministic, "change"),
		taskFixture(t, "memory", TaskRetrieveContext, "change"),
		taskFixture(t, "context", TaskAssembleContext, "analysis", "memory"),
		taskFixture(t, "candidates", TaskGenerateCandidates, "context"),
		taskFixture(t, "verification", TaskVerifyCandidates, "candidates"),
		taskFixture(t, "readiness", TaskEvaluatePublication, "verification"),
		mustTaskWithAttempts(t, "publication", TaskPublishResult, 1, "readiness"),
	}
}

func TestNewReviewRunPlanBuildsCanonicalSafeGraph(t *testing.T) {
	tasks := runPlanTasks(t)
	reverse := append([]TaskDefinition(nil), tasks...)
	for left, right := 0, len(reverse)-1; left < right; left, right = left+1, right-1 {
		reverse[left], reverse[right] = reverse[right], reverse[left]
	}
	plan, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunRequired, reverse)
	if err != nil || plan.Identity() == "" || plan.Mode() != ReviewRunRequired || plan.RequestIdentity() != strings.Repeat("b", 64) || plan.PolicyIdentity() != strings.Repeat("c", 64) || plan.TaskCount() != len(tasks) || plan.Validate() != nil {
		t.Fatalf("plan=(%#v,%v)", plan, err)
	}
	ordered := plan.Tasks()
	for index := 1; index < len(ordered); index++ {
		if ordered[index-1].Key() >= ordered[index].Key() {
			t.Fatalf("tasks not canonical: %#v", ordered)
		}
	}
	ordered[0] = TaskDefinition{}
	if plan.Tasks()[0].Identity() == "" {
		t.Fatal("plan exposed mutable tasks")
	}
	other, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunRequired, tasks)
	if err != nil || other.Identity() != plan.Identity() {
		t.Fatalf("canonical identity=(%#v,%v)", other, err)
	}
	publication, exists := plan.Task("publication")
	if !exists || publication.Kind() != TaskPublishResult {
		t.Fatalf("publication task=(%#v,%t)", publication, exists)
	}
	if strings.Contains(fmt.Sprintf("%#v", plan), strings.Repeat("b", 64)) {
		t.Fatal("plan formatting leaked identifiers")
	}
}

func TestNewReviewRunPlanRejectsUnsafeGraphs(t *testing.T) {
	scope := runScopeFixture(t)
	request, policy := strings.Repeat("b", 64), strings.Repeat("c", 64)
	cycleA := taskFixture(t, "a", TaskBuildChange, "b")
	cycleB := taskFixture(t, "b", TaskAcquireSource, "a")
	unknown := taskFixture(t, "change", TaskBuildChange, "missing")
	unsafeRetryTasks := runPlanTasks(t)
	for index, task := range unsafeRetryTasks {
		if task.Key() == "publication" {
			unsafeRetryTasks[index] = taskFixture(t, "publication", TaskPublishResult, "readiness")
		}
	}
	publish := taskFixture(t, "publication", TaskPublishResult, "source")
	for _, test := range []struct {
		name  string
		mode  ReviewRunMode
		tasks []TaskDefinition
		want  error
	}{
		{"empty", ReviewRunAdvisory, nil, ErrInvalidReviewRunTaskCount},
		{"cycle", ReviewRunAdvisory, []TaskDefinition{cycleA, cycleB}, ErrReviewRunTaskCycle},
		{"unknown dependency", ReviewRunAdvisory, []TaskDefinition{taskFixture(t, "source", TaskAcquireSource), unknown}, ErrReviewRunTaskDependencyMissing},
		{"duplicate", ReviewRunAdvisory, []TaskDefinition{taskFixture(t, "source", TaskAcquireSource), taskFixture(t, "source", TaskAcquireSource)}, ErrDuplicateReviewRunTask},
		{"unsafe publish", ReviewRunRequired, []TaskDefinition{taskFixture(t, "source", TaskAcquireSource), publish}, ErrReviewRunSafetyDependencyMissing},
		{"unsafe publication retry", ReviewRunRequired, unsafeRetryTasks, ErrReviewRunSafetyDependencyMissing},
		{"local publish", ReviewRunLocal, runPlanTasks(t), ErrReviewRunPublicationNotAllowed},
		{"advisory publish", ReviewRunAdvisory, runPlanTasks(t), ErrReviewRunPublicationNotAllowed},
		{"no source", ReviewRunAdvisory, []TaskDefinition{taskFixture(t, "analysis", TaskInspectDeterministic)}, ErrReviewRunSafetyDependencyMissing},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, err := NewReviewRunPlan(scope, request, policy, test.mode, test.tasks)
			if !errors.Is(err, test.want) || plan.Identity() != "" {
				t.Fatalf("NewReviewRunPlan()=(%#v,%v),want %v", plan, err, test.want)
			}
		})
	}
}

func TestTaskDefinitionRejectsInvalidBoundsAndDependencies(t *testing.T) {
	valid := strings.Repeat("a", 64)
	for _, test := range []struct {
		name, key    string
		kind         TaskKind
		input        string
		dependencies []string
		attempts     uint8
		retry        uint32
		lease        uint32
		want         error
	}{
		{"key", "Bad", TaskAcquireSource, valid, nil, 1, 0, 1000, ErrInvalidReviewTaskKey},
		{"kind", "task", 0, valid, nil, 1, 0, 1000, ErrInvalidReviewTaskKind},
		{"input", "task", TaskAcquireSource, "bad", nil, 1, 0, 1000, ErrInvalidReviewTaskInput},
		{"zero input", "task", TaskAcquireSource, strings.Repeat("0", 64), nil, 1, 0, 1000, ErrInvalidReviewTaskInput},
		{"attempts", "task", TaskAcquireSource, valid, nil, 0, 0, 1000, ErrInvalidReviewTaskAttempts},
		{"retry", "task", TaskAcquireSource, valid, nil, 1, maxReviewTaskLeaseMillis + 1, 1000, ErrInvalidReviewTaskRetry},
		{"lease", "task", TaskAcquireSource, valid, nil, 1, 0, 1, ErrInvalidReviewTaskLease},
		{"self", "task", TaskAcquireSource, valid, []string{"task"}, 1, 0, 1000, ErrReviewRunTaskSelfDependency},
		{"duplicate dependency", "task", TaskBuildChange, valid, []string{"source", "source"}, 1, 0, 1000, ErrDuplicateReviewTaskDependency},
	} {
		t.Run(test.name, func(t *testing.T) {
			task, err := NewTaskDefinition(test.key, test.kind, test.input, valid, test.dependencies, test.attempts, test.retry, test.lease, true)
			if !errors.Is(err, test.want) || task.Identity() != "" {
				t.Fatalf("NewTaskDefinition()=(%#v,%v),want %v", task, err, test.want)
			}
		})
	}
	if task, err := NewTaskDefinition("task", TaskAcquireSource, valid, "bad", nil, 1, 0, 1000, true); !errors.Is(err, ErrInvalidReviewTaskHandler) || task.Identity() != "" {
		t.Fatalf("invalid handler=(%#v,%v)", task, err)
	}
	task, _ := NewTaskDefinition("task", TaskBuildChange, valid, valid, []string{"z", "a"}, 2, 100, 1000, true)
	dependencies := task.Dependencies()
	if len(dependencies) != 2 || dependencies[0] != "a" || dependencies[1] != "z" {
		t.Fatalf("dependencies=%#v", dependencies)
	}
	dependencies[0] = "changed"
	if task.Dependencies()[0] != "a" {
		t.Fatal("task exposed mutable dependencies")
	}
}

func TestReviewRunPlanRejectsAmbiguousRequiredResultTask(t *testing.T) {
	_, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunAdvisory, []TaskDefinition{taskFixture(t, "source-a", TaskAcquireSource), taskFixture(t, "source-b", TaskAcquireSource)})
	if !errors.Is(err, ErrReviewRunResultTaskAmbiguous) {
		t.Fatalf("err=%v", err)
	}
}
