package webhook

import (
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"strings"
	"testing"
	"time"
)

type plannerStub struct {
	identity string
	plan     controlplane.ReviewRunPlan
	err      error
}

func (p plannerStub) Identity() string { return p.identity }
func (p plannerStub) Plan(context.Context, StoredDelivery) (controlplane.ReviewRunPlan, error) {
	return p.plan, p.err
}
func webhookRunPlan(t *testing.T, stored StoredDelivery) controlplane.ReviewRunPlan {
	t.Helper()
	delivery := stored.Delivery()
	scope, err := audit.NewReviewScope(delivery.Scope().TenantID(), delivery.Scope().RepositoryID(), ReviewRunIDForDelivery(delivery))
	if err != nil {
		t.Fatal(err)
	}
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, delivery.Identity(), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	plan, err := controlplane.NewReviewRunPlan(scope, delivery.Identity(), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
func TestProcessorCreatesReplaySafeRunFromAcceptedDelivery(t *testing.T) {
	delivery := inboxFixture(t, `{}`)
	store := NewMemoryStore()
	stored, _, _ := store.Put(context.Background(), delivery, time.UnixMilli(200))
	plan := webhookRunPlan(t, stored)
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	processor, err := NewProcessor(coordinator, plannerStub{identity: strings.Repeat("b", 64), plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	admission, state, err := processor.Process(context.Background(), stored, time.UnixMilli(300))
	if err != nil || admission.Validate() != nil || admission.PlanIdentity() != plan.Identity() || state.Status() != controlplane.ReviewRunActive {
		t.Fatalf("process=(%#v,%#v,%v)", admission, state, err)
	}
	again, next, err := processor.Process(context.Background(), stored, time.UnixMilli(400))
	if err != nil || again.Identity() != admission.Identity() || next.Identity() != state.Identity() {
		t.Fatalf("again=(%#v,%#v,%v)", again, next, err)
	}
}
func TestProcessorRejectsCrossScopeAndUnboundPlans(t *testing.T) {
	delivery := inboxFixture(t, `{}`)
	store := NewMemoryStore()
	stored, _, _ := store.Put(context.Background(), delivery, time.UnixMilli(200))
	valid := webhookRunPlan(t, stored)
	wrongScope, _ := audit.NewReviewScope("tenant-a", "repo-b", ReviewRunIDForDelivery(delivery))
	task, _ := valid.Task("source")
	crossScope, _ := controlplane.NewReviewRunPlan(wrongScope, delivery.Identity(), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	wrongRequest, _ := controlplane.NewReviewRunPlan(valid.Scope(), strings.Repeat("e", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	for _, plan := range []controlplane.ReviewRunPlan{crossScope, wrongRequest} {
		processor, _ := NewProcessor(coordinator, plannerStub{identity: strings.Repeat("b", 64), plan: plan})
		if got, state, err := processor.Process(context.Background(), stored, time.UnixMilli(300)); !errors.Is(err, ErrRunPlanNotBound) || got.Identity() != "" || state.Identity() != "" {
			t.Fatalf("process=(%#v,%#v,%v)", got, state, err)
		}
	}
}

type preparedPlannerStub struct {
	identity  string
	plan      controlplane.ReviewRunPlan
	artifacts []artifact.Artifact
	err       error
}

func (p preparedPlannerStub) Identity() string { return p.identity }
func (p preparedPlannerStub) Prepare(context.Context, StoredDelivery) (controlplane.ReviewRunPlan, []artifact.Artifact, error) {
	return p.plan, append([]artifact.Artifact(nil), p.artifacts...), p.err
}
func TestPreparedProcessorPersistsExactRootInputsBeforeOpeningRun(t *testing.T) {
	delivery := inboxFixture(t, `{}`)
	inbox := NewMemoryStore()
	stored, _, _ := inbox.Put(context.Background(), delivery, time.UnixMilli(200))
	scope, _ := audit.NewReviewScope(delivery.Scope().TenantID(), delivery.Scope().RepositoryID(), ReviewRunIDForDelivery(delivery))
	input, err := artifact.New(scope, artifact.KindTaskInput, "application/json", artifact.ClassificationRestricted, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{delivery.Identity()}, []byte(`{"recipe":"source"}`), time.UnixMilli(200), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, input.Identity(), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, delivery.Identity(), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	journal := controlplane.NewMemoryRunJournal()
	artifacts, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	processor, err := NewPreparedProcessor(journal, preparedPlannerStub{identity: strings.Repeat("b", 64), plan: plan, artifacts: []artifact.Artifact{input}}, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	admission, receipt, err := processor.Process(context.Background(), stored, time.UnixMilli(300))
	if err != nil || admission.PlanIdentity() != plan.Identity() || receipt.Status() != controlplane.ReviewRunActive {
		t.Fatalf("process=(%#v,%#v,%v)", admission, receipt, err)
	}
	storedInput, err := artifacts.Get(context.Background(), scope, input.Identity(), time.UnixMilli(300))
	if err != nil || storedInput.Identity() != input.Identity() {
		t.Fatalf("input=(%#v,%v)", storedInput, err)
	}
	again, resumed, err := processor.Process(context.Background(), stored, time.UnixMilli(2000))
	if err != nil || again.Identity() != admission.Identity() || resumed.Identity() != receipt.Identity() {
		t.Fatalf("expired replay=(%#v,%#v,%v)", again, resumed, err)
	}
	staleProcessor, _ := NewPreparedProcessor(controlplane.NewMemoryRunJournal(), preparedPlannerStub{identity: strings.Repeat("b", 64), plan: plan, artifacts: []artifact.Artifact{input}}, artifacts)
	if _, _, err := staleProcessor.Process(context.Background(), stored, time.UnixMilli(2000)); !errors.Is(err, ErrPreparedInputsExpired) {
		t.Fatalf("stale unopened err=%v", err)
	}
	staleSupervisor, _ := NewSupervisor(inbox, staleProcessor, delivery.Scope(), delivery.Source(), SupervisorOptions{QueueCapacity: 1, MaximumRetries: 1, RetryDelay: 10 * time.Millisecond, Clock: supervisorClock{time.UnixMilli(2000)}})
	if err := staleSupervisor.reconcile(context.Background()); err != nil {
		t.Fatalf("stale reconcile=%v", err)
	}
	secondInput, _ := artifact.New(scope, artifact.KindTaskInput, "application/json", artifact.ClassificationRestricted, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{delivery.Identity()}, []byte(`{"recipe":"second"}`), time.UnixMilli(200), time.UnixMilli(1000))
	secondTask, _ := controlplane.NewTaskDefinition("second", controlplane.TaskAcquireSource, secondInput.Identity(), strings.Repeat("e", 64), nil, 1, 1000, 30000, true)
	resultTask, _ := controlplane.NewTaskDefinition("result", controlplane.TaskBuildChange, strings.Repeat("f", 64), strings.Repeat("9", 64), []string{"source", "second"}, 1, 1000, 30000, true)
	twoRootPlan, err := controlplane.NewReviewRunPlan(scope, delivery.Identity(), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task, secondTask, resultTask})
	if err != nil {
		t.Fatal(err)
	}
	if err := persistPreparedInputs(context.Background(), artifacts, stored, twoRootPlan, []artifact.Artifact{input, input}, time.UnixMilli(2000)); !errors.Is(err, ErrRunPlanNotBound) {
		t.Fatalf("expired duplicate err=%v", err)
	}
	downstreamInput, _ := artifact.New(scope, artifact.KindTaskInput, "application/json", artifact.ClassificationRestricted, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{delivery.Identity()}, []byte(`{"recipe":"downstream"}`), time.UnixMilli(200), time.UnixMilli(1000))
	downstreamTask, _ := controlplane.NewTaskDefinition("result", controlplane.TaskBuildChange, downstreamInput.Identity(), strings.Repeat("9", 64), []string{"source"}, 1, 1000, 30000, true)
	preparedDownstreamPlan, _ := controlplane.NewReviewRunPlan(scope, delivery.Identity(), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task, downstreamTask})
	freshArtifacts, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	if err := persistPreparedInputs(context.Background(), freshArtifacts, stored, preparedDownstreamPlan, []artifact.Artifact{input, downstreamInput}, time.UnixMilli(300)); err != nil {
		t.Fatalf("prepared downstream input=%v", err)
	}
}
