package github

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	"github.com/georgejieh/open-trestle/webhook"
)

// The change and analysis handler identities an origin/main (29f6558) daemon
// bound, computed with that code; the analysis identity derived from analysis
// schema version 3.
const (
	mainChangeHandlerIdentity   = "1a574001085da1114defaf7d093fb91bb05abd684e40d3fc05cd2c20fdd0482d"
	mainAnalysisHandlerIdentity = "7b5bcfe63ff4dc765caa8e676fd7cc987b4d0c367348933a7a52172fd072068b"
)

type releaseTestClock struct{}

func (releaseTestClock) Now() time.Time { return time.UnixMilli(1000) }

// withHandlers is the advisory test bindings with the given change and
// analysis handler identities.
func withHandlers(change, analysis string) []TaskHandlerBinding {
	bindings := plannerBindings()[:8]
	for index := range bindings {
		switch bindings[index].Kind {
		case controlplane.TaskBuildChange:
			bindings[index].HandlerIdentity = change
		case controlplane.TaskInspectDeterministic:
			bindings[index].HandlerIdentity = analysis
		}
	}
	return bindings
}

// A run an origin/main daemon opened for a delivery names that release's
// handlers, which this daemon does not run, so it can neither be adopted nor
// make progress: it is refused with run_opened_by_incompatible_release, whose
// explanation says how to get a fresh review, and it is not advanced.
func TestPreparedProcessorRefusesARunAnIncompatibleReleaseOpened(t *testing.T) {
	ctx := context.Background()
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	if err != nil {
		t.Fatal(err)
	}
	change, err := changehandler.NewHandler(store, releaseTestClock{})
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := analysishandler.NewHandler(store, releaseTestClock{})
	if err != nil {
		t.Fatal(err)
	}
	if analysis.HandlerIdentity() == mainAnalysisHandlerIdentity {
		t.Fatal("the fixture needs a release whose handlers differ from origin/main's")
	}
	newPlanner := func(bindings []TaskHandlerBinding) *PreparedPullRequestPlanner {
		planner, err := NewBuiltInPreparedPullRequestPlanner("github.com", "owner/repository", strings.Repeat("e", 64), "tenant-github-review", controlplane.ReviewRunAdvisory, bindings, artifact.ClassificationRestricted, artifact.ProtectionProcessPrivate, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return planner
	}
	mainPlanner := newPlanner(withHandlers(mainChangeHandlerIdentity, mainAnalysisHandlerIdentity))
	current := newPlanner(withHandlers(change.HandlerIdentity(), analysis.HandlerIdentity()))
	base, head := strings.Repeat("1", 40), strings.Repeat("2", 40)
	stored := storedPullRequest(t, `{"action":"synchronize","number":42,"repository":{"full_name":"owner/repository"},"pull_request":{"base":{"sha":"`+base+`","repo":{"full_name":"owner/repository"}},"head":{"sha":"`+head+`","repo":{"full_name":"owner/repository"}}}}`)
	mainPlan, mainInputs := v1PreparedPlan(t, mainPlanner, stored, base, head)
	// The plan origin/main's planner opened for this delivery with those
	// handlers, computed with that code.
	if mainPlan.Identity() != "6938d229cd201060f4ee987fd89dde34d6f904fc25894f2d76748849461e2ab4" {
		t.Fatalf("origin/main fixture plan=%s", mainPlan.Identity())
	}
	for _, input := range mainInputs {
		if _, err := store.Put(ctx, input, stored.Receipt().AcceptedAt()); err != nil {
			t.Fatal(err)
		}
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	opened, err := coordinator.Open(ctx, mainPlan, time.UnixMilli(300))
	if err != nil {
		t.Fatal(err)
	}
	processor, err := webhook.NewPreparedProcessor(journal, current, store)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = processor.Process(ctx, stored, time.UnixMilli(400))
	if reason, refused := webhook.DeliveryRefusalReason(err); !refused || reason != webhook.RefusalReasonRunOpenedByIncompatibleRelease {
		t.Fatalf("a run origin/main opened was not refused as an incompatible release: reason=%s err=%v", reason, err)
	}
	if explanation := webhook.RefusalExplanation(webhook.RefusalReasonRunOpenedByIncompatibleRelease); !strings.Contains(explanation, "push a new commit") {
		t.Fatalf("explanation=%q", explanation)
	}
	if _, state, err := coordinator.Resume(ctx, mainPlan.Scope()); err != nil || state.Revision() != opened.Revision() {
		t.Fatalf("the incompatible run was advanced: %v", err)
	}
	// The same release's version 1 plan is still adopted.
	sameRelease := v1Journal(t, current, stored, base, head, store)
	adopter, _ := webhook.NewPreparedProcessor(sameRelease, current, store)
	if _, _, err := adopter.Process(ctx, stored, time.UnixMilli(400)); errors.Is(err, webhook.ErrDeliveryRefused) || err != nil {
		t.Fatalf("an exact-binding version 1 run was not adopted: %v", err)
	}
}

// v1Journal opens the version 1 plan the planner's own bindings produce.
func v1Journal(t *testing.T, planner *PreparedPullRequestPlanner, stored webhook.StoredDelivery, base, head string, store artifact.Store) controlplane.RunJournal {
	t.Helper()
	plan, inputs := v1PreparedPlan(t, planner, stored, base, head)
	for _, input := range inputs {
		if _, err := store.Put(context.Background(), input, stored.Receipt().AcceptedAt()); err != nil {
			t.Fatal(err)
		}
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	if _, err := coordinator.Open(context.Background(), plan, time.UnixMilli(300)); err != nil {
		t.Fatal(err)
	}
	return journal
}
