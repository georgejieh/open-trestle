package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

func startupContextPlan(t *testing.T, scope audit.ReviewScope, identity string) controlplane.ReviewRunPlan {
	t.Helper()
	makeTask := func(key string, kind controlplane.TaskKind, dependencies []string, handler string) controlplane.TaskDefinition {
		task, err := controlplane.NewTaskDefinition(key, kind, strings.Repeat("b", 64), handler, dependencies, 1, 0, 1000, true)
		if err != nil {
			t.Fatal(err)
		}
		return task
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("c", 64), strings.Repeat("d", 64), controlplane.ReviewRunLocal, []controlplane.TaskDefinition{
		makeTask("source", controlplane.TaskAcquireSource, nil, strings.Repeat("e", 64)),
		makeTask("change", controlplane.TaskBuildChange, []string{"source"}, strings.Repeat("f", 64)),
		makeTask("context", controlplane.TaskAssembleContext, []string{"change"}, identity),
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestLocalFullStartupRejectsActiveOldContextPlanWithoutMutation(t *testing.T) {
	args, getenv, _, _, _, _, _ := localFullDaemonFixture(t)
	d, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-old-context")
	old := startupContextPlan(t, scope, strings.Repeat("a", 64))
	coordinator, _ := controlplane.NewCoordinator(d.journal)
	before, err := coordinator.Open(context.Background(), old, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if restarted != nil {
		restarted.Close()
	}
	if !errors.Is(err, ErrDaemonPlanIncompatible) {
		t.Fatalf("startup incompatible=%v", err)
	}
	journal, err := controlplane.NewFileRunJournal(args[3])
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	saved, state, err := func() (controlplane.ReviewRunPlan, controlplane.ReviewRunState, error) {
		c, _ := controlplane.NewCoordinator(journal)
		return c.Resume(context.Background(), scope)
	}()
	if err != nil || saved.Identity() != old.Identity() || state.Revision() != before.Revision() {
		t.Fatalf("old plan mutated: revision=%d err=%v", state.Revision(), err)
	}
}

func TestLocalFullStartupAcceptsCurrentContextAndTerminalOldPlan(t *testing.T) {
	args, getenv, _, _, _, _, _ := localFullDaemonFixture(t)
	d, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	current := func() string {
		handler, err := contexthandler.NewPacketOnlyHandler(d.artifactStore, httpapi.SystemClock{})
		if err != nil {
			t.Fatal(err)
		}
		return handler.HandlerIdentity()
	}()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "current-context")
	plan := startupContextPlan(t, scope, current)
	c, _ := controlplane.NewCoordinator(d.journal)
	if _, err := c.Open(context.Background(), plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := checkLocalFullReviewStartupPlans(context.Background(), d.journal, "tenant-a", []string{"repo-a"}, current, strings.Repeat("f", 64)); err != nil {
		t.Fatalf("current plan rejected: %v", err)
	}
	terminalScope, _ := audit.NewReviewScope("tenant-a", "repo-a", "terminal-old")
	old := startupContextPlan(t, terminalScope, strings.Repeat("a", 64))
	now := time.Now().UTC()
	if _, err := c.Open(context.Background(), old, now); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CancelRun(context.Background(), old, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := checkLocalFullReviewStartupPlans(context.Background(), d.journal, "tenant-a", []string{"repo-a"}, current, strings.Repeat("f", 64)); err != nil {
		t.Fatalf("terminal plan rejected: %v", err)
	}
}

type failingStartupListJournal struct{ controlplane.RunJournal }

func (j failingStartupListJournal) ListPlans(context.Context, string, string, string, int) ([]controlplane.ReviewRunPlan, error) {
	return nil, fmt.Errorf("listing failed")
}
func TestLocalFullStartupFailsClosedOnListError(t *testing.T) {
	err := checkLocalFullReviewStartupPlans(context.Background(), failingStartupListJournal{controlplane.NewMemoryRunJournal()}, "tenant-a", []string{"repo-a"}, strings.Repeat("a", 64), strings.Repeat("f", 64))
	if err == nil || errors.Is(err, ErrDaemonPlanIncompatible) {
		t.Fatalf("listing failure=%v", err)
	}
}

type failingStartupReadJournal struct{ controlplane.RunJournal }

func (j failingStartupReadJournal) Read(context.Context, audit.ReviewScope, uint64, int) ([]controlplane.RunEvent, error) {
	return nil, fmt.Errorf("reading failed")
}

func TestLocalFullStartupFailsClosedOnReadError(t *testing.T) {
	journal := controlplane.NewMemoryRunJournal()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "read-fault")
	plan := startupContextPlan(t, scope, strings.Repeat("a", 64))
	coordinator, _ := controlplane.NewCoordinator(journal)
	if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	err := checkLocalFullReviewStartupPlans(context.Background(), failingStartupReadJournal{journal}, "tenant-a", []string{"repo-a"}, strings.Repeat("a", 64), strings.Repeat("f", 64))
	if err == nil || errors.Is(err, ErrDaemonPlanIncompatible) {
		t.Fatalf("read failure=%v", err)
	}
}

func TestLocalFullStartupChecksLaterPage(t *testing.T) {
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	current := strings.Repeat("a", 64)
	for index := 0; index < 101; index++ {
		scope, _ := audit.NewReviewScope("tenant-a", "repo-a", fmt.Sprintf("run-%03d", index))
		identity := current
		if index == 100 {
			identity = strings.Repeat("b", 64)
		}
		plan := startupContextPlan(t, scope, identity)
		if _, err := coordinator.Open(context.Background(), plan, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkLocalFullReviewStartupPlans(context.Background(), journal, "tenant-a", []string{"repo-a"}, current, strings.Repeat("f", 64)); !errors.Is(err, ErrDaemonPlanIncompatible) {
		t.Fatalf("later page incompatible=%v", err)
	}
}

func TestLocalFullStartupRejectsActiveLegacyAnalysisWithoutMutatingOrBlockingTerminal(t *testing.T) {
	args, getenv, repository, base, head, policy, inventory := localFullDaemonFixture(t)
	d, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "legacy-analysis-template")
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(d.server.Handler)
	api, err := client.NewLocal(server.URL, getenv("OPEN_TRESTLE_API_TOKEN"), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.SubmitLocalFullReview(ctx, intent); err != nil {
		t.Fatal(err)
	}
	template, err := api.GetRunPlan(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	oldTasks := make([]controlplane.TaskDefinition, 0, template.TaskCount())
	for _, task := range template.Tasks() {
		identity := task.HandlerIdentity()
		if task.Key() == "analysis" {
			identity = strings.Repeat("a", 64)
		}
		old, err := controlplane.NewTaskDefinition(task.Key(), task.Kind(), task.InputIdentity(), identity, task.Dependencies(), task.MaxAttempts(), task.RetryDelayMilliseconds(), task.LeaseDurationMilliseconds(), task.Required())
		if err != nil {
			t.Fatal(err)
		}
		oldTasks = append(oldTasks, old)
	}
	activeScope, _ := audit.NewReviewScope("tenant-a", "repo-a", "legacy-analysis-active")
	legacy, err := controlplane.NewReviewRunPlan(activeScope, template.RequestIdentity(), template.PolicyIdentity(), template.Mode(), oldTasks)
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, _ := controlplane.NewCoordinator(journal)
	before, err := coordinator.Open(ctx, legacy, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := checkLocalFullReviewStartupPlans(ctx, journal, "tenant-a", []string{"repo-a"}, templateTaskIdentity(t, template, "context"), templateTaskIdentity(t, template, "analysis")); !errors.Is(err, ErrDaemonPlanIncompatible) {
		t.Fatalf("active legacy analysis accepted: %v", err)
	}
	_, after, err := coordinator.Resume(ctx, activeScope)
	if err != nil || after.Revision() != before.Revision() || after.HeadIdentity() != before.HeadIdentity() {
		t.Fatalf("active scope mutated: %v", err)
	}
	if _, err := coordinator.CancelRun(ctx, legacy, time.Now().UTC().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := checkLocalFullReviewStartupPlans(ctx, journal, "tenant-a", []string{"repo-a"}, templateTaskIdentity(t, template, "context"), templateTaskIdentity(t, template, "analysis")); err != nil {
		t.Fatalf("terminal legacy scope refused: %v", err)
	}
}

func TestLocalFullStartupIgnoresNonFullAnalysisHandlerMismatch(t *testing.T) {
	ctx := context.Background()
	journal := controlplane.NewMemoryRunJournal()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "deterministic-analysis")
	constant := strings.Repeat("a", 64)
	makeTask := func(key string, kind controlplane.TaskKind, deps []string, handler string) controlplane.TaskDefinition {
		t.Helper()
		task, err := controlplane.NewTaskDefinition(key, kind, constant, handler, deps, 1, 0, 1000, true)
		if err != nil {
			t.Fatal(err)
		}
		return task
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunLocal, []controlplane.TaskDefinition{
		makeTask("source-base", controlplane.TaskAcquireSource, nil, constant),
		makeTask("source-head", controlplane.TaskAcquireSource, nil, constant),
		makeTask("change", controlplane.TaskBuildChange, []string{"source-base", "source-head"}, constant),
		makeTask("analysis", controlplane.TaskInspectDeterministic, []string{"change"}, constant),
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(journal)
	if _, err := coordinator.Open(ctx, plan, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if isLocalFullReviewPlan(plan) {
		t.Fatal("deterministic plan misclassified as full review")
	}
	if err := checkLocalFullReviewStartupPlans(ctx, journal, "tenant-a", []string{"repo-a"}, strings.Repeat("d", 64), strings.Repeat("e", 64)); err != nil {
		t.Fatalf("deterministic-only analysis mismatch refused: %v", err)
	}
}

func templateTaskIdentity(t *testing.T, plan controlplane.ReviewRunPlan, key string) string {
	t.Helper()
	task, exists := plan.Task(key)
	if !exists {
		t.Fatalf("missing task %s", key)
	}
	return task.HandlerIdentity()
}
