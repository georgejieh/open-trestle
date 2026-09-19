package github

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	publicationhandler "github.com/georgejieh/open-trestle/handlers/publication"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/webhook"
)

func plannerBindings() []TaskHandlerBinding {
	kinds := []controlplane.TaskKind{controlplane.TaskAcquireSource, controlplane.TaskBuildChange, controlplane.TaskInspectDeterministic, controlplane.TaskRetrieveContext, controlplane.TaskAssembleContext, controlplane.TaskGenerateCandidates, controlplane.TaskVerifyCandidates, controlplane.TaskEvaluatePublication, controlplane.TaskPublishResult}
	bindings := make([]TaskHandlerBinding, len(kinds))
	for index, kind := range kinds {
		bindings[index] = TaskHandlerBinding{Kind: kind, HandlerIdentity: fmt.Sprintf("%064x", index+1)}
	}
	return bindings
}
func storedPullRequest(t *testing.T, payload string) webhook.StoredDelivery {
	t.Helper()
	scope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	delivery, err := webhook.NewVerifiedDelivery(scope, webhook.SourceGitHub, "delivery-1", "pull_request", "synchronize", strings.Repeat("f", 64), []byte(payload), time.UnixMilli(100))
	if err != nil {
		t.Fatal(err)
	}
	store := webhook.NewMemoryStore()
	stored, _, err := store.Put(context.Background(), delivery, time.UnixMilli(200))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}
func TestPullRequestPlannerBuildsStableBoundPlan(t *testing.T) {
	planner, err := NewPullRequestPlanner("owner/repository", strings.Repeat("e", 64), controlplane.ReviewRunRequired, plannerBindings())
	if err != nil {
		t.Fatal(err)
	}
	if planner.Identity() != "7a76ea3f65d705f48c699c1f1c19eea04256fb592a05da3dd7ee8ae395da1588" {
		t.Fatalf("planner identity=%s", planner.Identity())
	}
	payload := `{"action":"synchronize","number":42,"repository":{"full_name":"Owner/Repository"},"pull_request":{"base":{"sha":"1111111111111111111111111111111111111111","repo":{"full_name":"owner/repository"}},"head":{"sha":"2222222222222222222222222222222222222222","repo":{"full_name":"owner/repository"}}}}`
	stored := storedPullRequest(t, payload)
	plan, err := planner.Plan(context.Background(), stored)
	if err != nil || plan.Validate() != nil || plan.RequestIdentity() != stored.Delivery().Identity() || plan.Scope().ReviewRunID() != webhook.ReviewRunIDForDelivery(stored.Delivery()) || plan.TaskCount() != 9 {
		t.Fatalf("plan=(%#v,%v)", plan, err)
	}
	again, err := planner.Plan(context.Background(), stored)
	if err != nil || again.Identity() != plan.Identity() {
		t.Fatalf("again=(%#v,%v)", again, err)
	}
	publication, found := plan.Task("publication")
	if !found || publication.MaxAttempts() != 1 {
		t.Fatalf("publication=(%#v,%t)", publication, found)
	}
	readiness, found := plan.Task("readiness")
	if !found || !equalPlannerDependencies(readiness.Dependencies(), []string{"analysis", "change", "verification"}) {
		t.Fatalf("readiness=(%#v,%t)", readiness, found)
	}
	for _, key := range []string{"candidates", "verification"} {
		task, found := plan.Task(key)
		if !found || task.MaxAttempts() != 1 {
			t.Fatalf("%s=(%#v,%t)", key, task, found)
		}
	}
}
func TestPreparedPlannerRejectsForkPullRequest(t *testing.T) {
	planner, err := NewBuiltInPreparedPullRequestPlanner("github.com", "owner/repository", strings.Repeat("e", 64), "tenant-github-review", controlplane.ReviewRunRequired, plannerBindings(), artifact.ClassificationRestricted, artifact.ProtectionProcessPrivate, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"action":"synchronize","number":42,"repository":{"full_name":"owner/repository"},"pull_request":{"base":{"sha":"1111111111111111111111111111111111111111","repo":{"full_name":"owner/repository"}},"head":{"sha":"2222222222222222222222222222222222222222","repo":{"full_name":"contributor/repository"}}}}`
	stored := storedPullRequest(t, payload)
	if _, _, err := planner.Prepare(context.Background(), stored); !errors.Is(err, ErrInvalidPullRequestPayload) {
		t.Fatalf("prepare err=%v", err)
	}
}

func TestPullRequestPlannerRejectsAmbiguousOrCrossRepositoryPayload(t *testing.T) {
	planner, _ := NewPullRequestPlanner("owner/repository", strings.Repeat("e", 64), controlplane.ReviewRunRequired, plannerBindings())
	payloads := []string{`{"action":"synchronize","number":1,"number":2,"repository":{"full_name":"owner/repository"},"pull_request":{"base":{"sha":"1111111111111111111111111111111111111111","repo":{"full_name":"owner/repository"}},"head":{"sha":"2222222222222222222222222222222222222222","repo":{"full_name":"owner/repository"}}}}`, `{"action":"synchronize","number":1,"repository":{"full_name":"other/repository"},"pull_request":{"base":{"sha":"1111111111111111111111111111111111111111","repo":{"full_name":"owner/repository"}},"head":{"sha":"2222222222222222222222222222222222222222","repo":{"full_name":"owner/repository"}}}}`}
	for _, payload := range payloads {
		if plan, err := planner.Plan(context.Background(), storedPullRequest(t, payload)); !errors.Is(err, ErrInvalidPullRequestPayload) || plan.Identity() != "" {
			t.Fatalf("plan=(%#v,%v)", plan, err)
		}
	}
}

func TestPreparedPullRequestPlannerMaterializesExactBaseAndHeadInputs(t *testing.T) {
	planner, err := NewBuiltInPreparedPullRequestPlanner("github.com", "owner/repository", strings.Repeat("e", 64), "tenant-github-review", controlplane.ReviewRunRequired, plannerBindings(), artifact.ClassificationRestricted, artifact.ProtectionProcessPrivate, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	payload := `{"action":"synchronize","number":42,"repository":{"full_name":"owner/repository"},"pull_request":{"base":{"sha":"1111111111111111111111111111111111111111","repo":{"full_name":"owner/repository"}},"head":{"sha":"2222222222222222222222222222222222222222","repo":{"full_name":"owner/repository"}}}}`
	stored := storedPullRequest(t, payload)
	plan, inputs, err := planner.Prepare(context.Background(), stored)
	if err != nil || plan.Validate() != nil || plan.TaskCount() != 10 || len(inputs) != 3 {
		t.Fatalf("prepared=(%#v,%d,%v)", plan, len(inputs), err)
	}
	revisions := map[string]bool{}
	publicationFound := false
	for _, value := range inputs {
		if input, sourceErr := sourcehandler.ParseInput(value.Payload()); sourceErr == nil {
			if value.Scope().Identity() != plan.Scope().Identity() || value.CreatedAt() != stored.Receipt().AcceptedAt() || input.Repository().Authority() != "github.com" || input.Repository().Namespace()[0] != "owner" {
				t.Fatalf("input=%#v", input)
			}
			revisions[input.Revision().Digest()] = true
			continue
		}
		publicationInput, publicationErr := publicationhandler.ParseInput(value.Payload())
		if publicationErr != nil {
			t.Fatal(publicationErr)
		}
		target, targetErr := publicationInput.Target()
		if targetErr != nil || target.ChangeID() != "42" || target.PublisherID() != "tenant-github-review" || target.HeadRevision().Digest() != strings.Repeat("2", 40) {
			t.Fatalf("publication target=(%#v,%v)", target, targetErr)
		}
		publicationFound = true
	}
	if !publicationFound {
		t.Fatal("publication input missing")
	}
	if !revisions[strings.Repeat("1", 40)] || !revisions[strings.Repeat("2", 40)] {
		t.Fatalf("revisions=%v", revisions)
	}
	baseTask, _ := plan.Task("source-base")
	headTask, _ := plan.Task("source-head")
	change, _ := plan.Task("change")
	readiness, _ := plan.Task("readiness")
	publicationTask, _ := plan.Task("publication")
	publicationInputFound := false
	for _, value := range inputs {
		if value.Identity() == publicationTask.InputIdentity() {
			publicationInputFound = true
		}
	}
	if baseTask.InputIdentity() == headTask.InputIdentity() || len(change.Dependencies()) != 2 || !equalPlannerDependencies(readiness.Dependencies(), []string{"analysis", "change", "verification"}) || !publicationInputFound {
		t.Fatalf("tasks=%#v/%#v/%#v", baseTask, headTask, change)
	}
	again, againInputs, err := planner.Prepare(context.Background(), stored)
	otherPublisher, _ := NewBuiltInPreparedPullRequestPlanner("github.com", "owner/repository", strings.Repeat("e", 64), "other-github-review", controlplane.ReviewRunRequired, plannerBindings(), artifact.ClassificationRestricted, artifact.ProtectionProcessPrivate, 24*time.Hour)
	if otherPublisher.Identity() == planner.Identity() {
		t.Fatal("publisher identity did not bind planner")
	}
	if err != nil || again.Identity() != plan.Identity() || againInputs[0].Identity() != inputs[0].Identity() || planner.Identity() == "" {
		t.Fatalf("repeat=(%#v,%v)", again, err)
	}
}

func TestPullRequestPlannerRejectsUnusedHandlerAuthority(t *testing.T) {
	bindings := plannerBindings()
	if planner, err := NewPullRequestPlanner("owner/repository", strings.Repeat("e", 64), controlplane.ReviewRunAdvisory, bindings); !errors.Is(err, ErrInvalidPullRequestPlanner) || planner != nil {
		t.Fatalf("planner=(%#v,%v)", planner, err)
	}
	planner, err := NewPullRequestPlanner("owner/repository", strings.Repeat("e", 64), controlplane.ReviewRunAdvisory, bindings[:8])
	if err != nil || planner == nil {
		t.Fatalf("exact planner=(%#v,%v)", planner, err)
	}
}

func equalPlannerDependencies(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}
