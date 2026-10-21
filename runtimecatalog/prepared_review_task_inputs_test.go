package runtimecatalog

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/controlplane"
)

func taskInputRecipePrepared(t *testing.T, deterministic bool) PreparedReviewRun {
	t.Helper()
	options := preparedReviewOptions(t)
	if deterministic {
		var err error
		options.Catalog, err = NewPipelineCatalog(controlplane.ReviewRunLocal, []controlplane.TaskHandler{handler{controlplane.TaskAcquireSource, strings.Repeat("1", 64)}, handler{controlplane.TaskBuildChange, strings.Repeat("2", 64)}, handler{controlplane.TaskInspectDeterministic, strings.Repeat("3", 64)}})
		if err != nil {
			t.Fatal(err)
		}
		options.InventoryIdentity = ""
		options.RuntimePolicyIdentity = ""
	}
	request, err := NewPreparedReviewRequest(options)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareReviewRun(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func taskInputRecipePlan(t *testing.T, plan controlplane.ReviewRunPlan, key, input, request string) controlplane.ReviewRunPlan {
	t.Helper()
	tasks := plan.Tasks()
	for i, task := range tasks {
		if task.Key() == key {
			changed, err := controlplane.NewTaskDefinition(task.Key(), task.Kind(), input, task.HandlerIdentity(), task.Dependencies(), task.MaxAttempts(), task.RetryDelayMilliseconds(), task.LeaseDurationMilliseconds(), task.Required())
			if err != nil {
				t.Fatal(err)
			}
			tasks[i] = changed
		}
	}
	if request == "" {
		request = plan.RequestIdentity()
	}
	changed, err := controlplane.NewReviewRunPlan(plan.Scope(), request, plan.PolicyIdentity(), plan.Mode(), tasks)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func TestPreparedReviewPlanTaskInputsFullAndDeterministic(t *testing.T) {
	for _, deterministic := range []bool{false, true} {
		prepared := taskInputRecipePrepared(t, deterministic)
		plan := prepared.Plan()
		before, err := controlplane.EncodeReviewRunPlan(plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidatePreparedReviewPlanTaskInputs(plan); err != nil {
			t.Fatal(err)
		}
		after, err := controlplane.EncodeReviewRunPlan(plan)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("validator changed plan wire", err)
		}
		// Lock the pre-existing builder's exact preimage, including dependency TASK
		// identities ordered by dependency keys rather than output IDs/digest sort.
		for _, task := range plan.Tasks() {
			if task.Kind() == controlplane.TaskAcquireSource {
				continue
			}
			deps := []string{}
			for _, key := range task.Dependencies() {
				dependency, _ := plan.Task(key)
				deps = append(deps, dependency.Identity())
			}
			want := preparedDigest([]any{"open-trestle/prepared-review-task-input", 1, plan.RequestIdentity(), task.Kind().String(), deps})
			if task.InputIdentity() != want {
				t.Fatal("builder recipe changed", task.Key())
			}
		}
	}
}

func TestPreparedReviewPlanTaskInputsRejectsEachRecordedInputMutation(t *testing.T) {
	plan := taskInputRecipePrepared(t, false).Plan()
	count := 0
	for _, task := range plan.Tasks() {
		if task.Kind() == controlplane.TaskAcquireSource {
			continue
		}
		count++
		t.Run(task.Key(), func(t *testing.T) {
			changed := taskInputRecipePlan(t, plan, task.Key(), strings.Repeat("f", 64), "")
			if err := ValidatePreparedReviewPlanTaskInputs(changed); !errors.Is(err, ErrInvalidPreparedReview) {
				t.Fatal("unrecorded input accepted", err)
			}
		})
	}
	if count != 7 {
		t.Fatal("fixture no longer full seven hashed inputs", count)
	}
	changed := taskInputRecipePlan(t, plan, "", "", strings.Repeat("f", 64))
	if err := ValidatePreparedReviewPlanTaskInputs(changed); !errors.Is(err, ErrInvalidPreparedReview) {
		t.Fatal("stale request recipe accepted", err)
	}
	// Changing a source task's input changes its task identity, so its direct
	// dependents' old hashes must fail even though source inputs are not hashed.
	changed = taskInputRecipePlan(t, plan, "source-base", strings.Repeat("f", 64), "")
	if err := ValidatePreparedReviewPlanTaskInputs(changed); !errors.Is(err, ErrInvalidPreparedReview) {
		t.Fatal("stale dependency task recipe accepted", err)
	}
}

func TestPreparedReviewPlanTaskInputsSourceArtifactAndShapeLimit(t *testing.T) {
	plan := taskInputRecipePrepared(t, false).Plan()
	source, _ := plan.Task("source-base")
	changed, err := controlplane.NewReviewRunPlan(plan.Scope(), plan.RequestIdentity(), plan.PolicyIdentity(), controlplane.ReviewRunLocal, []controlplane.TaskDefinition{source})
	if err != nil {
		t.Fatal(err)
	}
	changed = taskInputRecipePlan(t, changed, "source-base", strings.Repeat("f", 64), "")
	if err := ValidatePreparedReviewPlanTaskInputs(changed); err != nil {
		t.Fatal("source artifact identity was treated as hashed recipe", err)
	}
	// Recipe validation does not claim nine-task shape, source artifact presence,
	// catalog enrollment or startup admission.
	if err := ValidatePreparedReviewPlanTaskInputs(controlplane.ReviewRunPlan{}); !errors.Is(err, ErrInvalidPreparedReview) {
		t.Fatal("invalid plan accepted", err)
	}
	nonlocal, err := controlplane.NewReviewRunPlan(plan.Scope(), plan.RequestIdentity(), plan.PolicyIdentity(), controlplane.ReviewRunAdvisory, plan.Tasks())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePreparedReviewPlanTaskInputs(nonlocal); !errors.Is(err, ErrInvalidPreparedReview) {
		t.Fatal("nonlocal plan accepted", err)
	}
}
