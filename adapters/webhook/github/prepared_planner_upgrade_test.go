package github

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/webhook"
)

// v1PreparedPlan rebuilds the plan the version 1 prepared planner opened for a
// delivery: both source tasks named their commit directly.
func v1PreparedPlan(t *testing.T, planner *PreparedPullRequestPlanner, stored webhook.StoredDelivery, base, head string) (controlplane.ReviewRunPlan, []artifact.Artifact) {
	t.Helper()
	scope, payload, err := planner.base.parseDelivery(context.Background(), stored, false)
	if err != nil {
		t.Fatal(err)
	}
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repository")
	created := stored.Receipt().AcceptedAt()
	inputs := make([]artifact.Artifact, 0, 2)
	for _, digest := range []string{base, head} {
		revision, _ := plannerRevision(digest)
		input, err := sourcehandler.NewInput(repository, revision, planner.sourceAdapter)
		if err != nil {
			t.Fatal(err)
		}
		value, err := sourcehandler.NewInputArtifact(scope, input, planner.classification, planner.protection, []string{stored.Delivery().Identity()}, created, created.Add(planner.retention))
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, value)
	}
	tasks, err := planner.tasks(stored.Delivery(), payload.Number, base, head, inputs[0].Identity(), inputs[1].Identity(), "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, stored.Delivery().Identity(), planner.base.policyIdentity, planner.base.mode, tasks)
	if err != nil {
		t.Fatal(err)
	}
	return plan, inputs
}

// A delivery whose run was opened by the version 1 planner is that delivery's
// run: reprocessing after the upgrade resumes it instead of refusing it.
func TestPreparedProcessorResumesARunOpenedByTheVersion1Planner(t *testing.T) {
	ctx := context.Background()
	planner, err := NewBuiltInPreparedPullRequestPlanner("github.com", "owner/repository", strings.Repeat("e", 64), "tenant-github-review", controlplane.ReviewRunAdvisory, plannerBindings()[:8], artifact.ClassificationRestricted, artifact.ProtectionProcessPrivate, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	base, head := strings.Repeat("1", 40), strings.Repeat("2", 40)
	stored := storedPullRequest(t, `{"action":"synchronize","number":42,"repository":{"full_name":"owner/repository"},"pull_request":{"base":{"sha":"`+base+`","repo":{"full_name":"owner/repository"}},"head":{"sha":"`+head+`","repo":{"full_name":"owner/repository"}}}}`)
	journal := controlplane.NewMemoryRunJournal()
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	if err != nil {
		t.Fatal(err)
	}
	v1Plan, v1Inputs := v1PreparedPlan(t, planner, stored, base, head)
	// The identity the version 1 planner (origin/main 29f6558) produced for
	// this delivery, computed with that code.
	if v1Plan.Identity() != "cc07e7034cebe5c0cb3f2a91a8e88f3840b4bff2221864d7d0feef269fa7875a" {
		t.Fatalf("version 1 fixture plan=%s", v1Plan.Identity())
	}
	for _, input := range v1Inputs {
		if _, err := store.Put(ctx, input, stored.Receipt().AcceptedAt()); err != nil {
			t.Fatal(err)
		}
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(ctx, v1Plan, time.UnixMilli(300)); err != nil {
		t.Fatal(err)
	}
	current, _, err := planner.Prepare(ctx, stored)
	if err != nil || current.Identity() == v1Plan.Identity() {
		t.Fatalf("fixture must differ from the version 2 plan: %v", err)
	}
	processor, err := webhook.NewPreparedProcessor(journal, planner, store)
	if err != nil {
		t.Fatal(err)
	}
	admission, receipt, err := processor.Process(ctx, stored, time.UnixMilli(400))
	if err != nil {
		t.Fatalf("version 1 run was not resumed: %v", err)
	}
	if admission.PlanIdentity() != v1Plan.Identity() || receipt.PlanIdentity() != v1Plan.Identity() || receipt.Status() != controlplane.ReviewRunActive {
		t.Fatal("reprocessing did not report the version 1 run")
	}
	task, _ := receipt.Task("source-base")
	if task.InputIdentity() != v1Inputs[0].Identity() || task.Status() != controlplane.TaskRuntimeAvailable {
		t.Fatalf("version 1 source-base task status=%s", task.Status())
	}
	if _, _, err := processor.Process(ctx, stored, time.UnixMilli(500)); err != nil {
		t.Fatalf("repeat reprocessing failed: %v", err)
	}
	if _, err := store.Get(ctx, v1Plan.Scope(), current.Tasks()[0].InputIdentity(), time.UnixMilli(500)); !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("resuming wrote version 2 inputs beside the version 1 run: %v", err)
	}
}

// The planner names the plan its version 1 produced for a delivery, in both
// modes, with the identities that code produced, and none for a delivery
// version 1 could not plan.
func TestPreparedPlannerNamesTheVersion1Plan(t *testing.T) {
	ctx := context.Background()
	base, head := strings.Repeat("1", 40), strings.Repeat("2", 40)
	payload := func(base, head string) string {
		return `{"action":"synchronize","number":42,"repository":{"full_name":"owner/repository"},"pull_request":{"base":{"sha":"` + base + `","repo":{"full_name":"owner/repository"}},"head":{"sha":"` + head + `","repo":{"full_name":"owner/repository"}}}}`
	}
	for _, c := range []struct {
		mode     controlplane.ReviewRunMode
		bindings []TaskHandlerBinding
		v1       string
	}{
		{controlplane.ReviewRunAdvisory, plannerBindings()[:8], "cc07e7034cebe5c0cb3f2a91a8e88f3840b4bff2221864d7d0feef269fa7875a"},
		{controlplane.ReviewRunRequired, plannerBindings(), "81ff5fcd9e10a23e5cae4056c702c251aeed173fcdc9c803abbcb005459bac35"},
	} {
		planner, err := NewBuiltInPreparedPullRequestPlanner("github.com", "owner/repository", strings.Repeat("e", 64), "tenant-github-review", c.mode, c.bindings, artifact.ClassificationRestricted, artifact.ProtectionProcessPrivate, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		identities, err := planner.SupersededPlanIdentities(ctx, storedPullRequest(t, payload(base, head)))
		if err != nil || len(identities) != 1 || identities[0] != c.v1 {
			t.Fatalf("%s version 1 plans=%v err=%v", c.mode, identities, err)
		}
		if identities, err := planner.SupersededPlanIdentities(ctx, storedPullRequest(t, payload(head, head))); err != nil || len(identities) != 0 {
			t.Fatalf("%s version 1 plans for equal commits=%v err=%v", c.mode, identities, err)
		}
	}
}

// A run in the delivery's scope whose plan names the delivery's request but
// is not one this planner or its version 1 produces (for example opened by a
// caller with other tasks) is not the delivery's run: it is a conflict, and
// it is neither adopted nor advanced.
func TestPreparedProcessorRefusesAPlanThePlannerDidNotProduce(t *testing.T) {
	ctx := context.Background()
	planner, err := NewBuiltInPreparedPullRequestPlanner("github.com", "owner/repository", strings.Repeat("e", 64), "tenant-github-review", controlplane.ReviewRunAdvisory, plannerBindings()[:8], artifact.ClassificationRestricted, artifact.ProtectionProcessPrivate, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	base, head := strings.Repeat("1", 40), strings.Repeat("2", 40)
	stored := storedPullRequest(t, `{"action":"synchronize","number":42,"repository":{"full_name":"owner/repository"},"pull_request":{"base":{"sha":"`+base+`","repo":{"full_name":"owner/repository"}},"head":{"sha":"`+head+`","repo":{"full_name":"owner/repository"}}}}`)
	current, _, err := planner.Prepare(ctx, stored)
	if err != nil {
		t.Fatal(err)
	}
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, 2, 100, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := controlplane.NewReviewRunPlan(current.Scope(), stored.Delivery().Identity(), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	opened, err := coordinator.Open(ctx, foreign, time.UnixMilli(300))
	if err != nil {
		t.Fatal(err)
	}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	processor, err := webhook.NewPreparedProcessor(journal, planner, store)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = processor.Process(ctx, stored, time.UnixMilli(400))
	if reason, refused := webhook.DeliveryRefusalReason(err); !refused || reason != webhook.RefusalReasonRunPlanConflict || !errors.Is(err, controlplane.ErrRunPlanConflict) {
		t.Fatalf("a plan the planner did not produce was adopted: %v", err)
	}
	if _, state, err := coordinator.Resume(ctx, current.Scope()); err != nil || state.Revision() != opened.Revision() {
		t.Fatalf("the foreign run was advanced: %v", err)
	}
}

// A run whose plan was opened for another request is not this delivery's run.
func TestPreparedProcessorRefusesARunOpenedForAnotherRequest(t *testing.T) {
	ctx := context.Background()
	planner, err := NewBuiltInPreparedPullRequestPlanner("github.com", "owner/repository", strings.Repeat("e", 64), "tenant-github-review", controlplane.ReviewRunAdvisory, plannerBindings()[:8], artifact.ClassificationRestricted, artifact.ProtectionProcessPrivate, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	base, head := strings.Repeat("1", 40), strings.Repeat("2", 40)
	stored := storedPullRequest(t, `{"action":"synchronize","number":42,"repository":{"full_name":"owner/repository"},"pull_request":{"base":{"sha":"`+base+`","repo":{"full_name":"owner/repository"}},"head":{"sha":"`+head+`","repo":{"full_name":"owner/repository"}}}}`)
	v1Plan, _ := v1PreparedPlan(t, planner, stored, base, head)
	foreign, err := controlplane.NewReviewRunPlan(v1Plan.Scope(), strings.Repeat("9", 64), v1Plan.PolicyIdentity(), v1Plan.Mode(), v1Plan.Tasks())
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	if _, err := coordinator.Open(ctx, foreign, time.UnixMilli(300)); err != nil {
		t.Fatal(err)
	}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	processor, err := webhook.NewPreparedProcessor(journal, planner, store)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = processor.Process(ctx, stored, time.UnixMilli(400))
	if reason, refused := webhook.DeliveryRefusalReason(err); !refused || reason != webhook.RefusalReasonRunPlanConflict || !errors.Is(err, controlplane.ErrRunPlanConflict) {
		t.Fatalf("foreign run err=%v", err)
	}
}
