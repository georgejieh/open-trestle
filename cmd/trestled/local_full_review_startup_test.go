package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
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
	if err := checkLocalFullReviewStartupPlans(context.Background(), d.journal, "tenant-a", []string{"repo-a"}, current); err != nil {
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
	if err := checkLocalFullReviewStartupPlans(context.Background(), d.journal, "tenant-a", []string{"repo-a"}, current); err != nil {
		t.Fatalf("terminal plan rejected: %v", err)
	}
}

type failingStartupListJournal struct{ controlplane.RunJournal }

func (j failingStartupListJournal) ListPlans(context.Context, string, string, string, int) ([]controlplane.ReviewRunPlan, error) {
	return nil, fmt.Errorf("listing failed")
}
func TestLocalFullStartupFailsClosedOnListError(t *testing.T) {
	err := checkLocalFullReviewStartupPlans(context.Background(), failingStartupListJournal{controlplane.NewMemoryRunJournal()}, "tenant-a", []string{"repo-a"}, strings.Repeat("a", 64))
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
	err := checkLocalFullReviewStartupPlans(context.Background(), failingStartupReadJournal{journal}, "tenant-a", []string{"repo-a"}, strings.Repeat("a", 64))
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
	if err := checkLocalFullReviewStartupPlans(context.Background(), journal, "tenant-a", []string{"repo-a"}, current); !errors.Is(err, ErrDaemonPlanIncompatible) {
		t.Fatalf("later page incompatible=%v", err)
	}
}
