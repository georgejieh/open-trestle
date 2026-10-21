package controlplane

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestHistoricalPacketTransitiveSuccessSnapshot(t *testing.T) {
	ctx := context.Background()
	tasks := []TaskDefinition{
		taskFixture(t, "source-base", TaskAcquireSource), taskFixture(t, "source-head", TaskAcquireSource),
		taskFixture(t, "change", TaskBuildChange, "source-base", "source-head"),
		taskFixture(t, "analysis", TaskInspectDeterministic, "change"), taskFixture(t, "memory", TaskRetrieveContext, "change"),
		taskFixture(t, "context", TaskAssembleContext, "analysis", "memory"),
		taskFixture(t, "candidates", TaskGenerateCandidates, "context"), taskFixture(t, "verification", TaskVerifyCandidates, "candidates"),
		taskFixture(t, "readiness", TaskEvaluatePublication, "analysis", "change", "verification"),
	}
	plan, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunLocal, tasks)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	coordinator := inventoryOpen(t, journal, plan)
	at := time.UnixMilli(200)
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory"} {
		task, _ := plan.Task(key)
		lease, ok, err := coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", at)
		if err != nil || !ok {
			t.Fatalf("claim %s: %v", key, err)
		}
		success, _ := NewTaskSuccess(strings.Repeat("e", 64))
		if _, err := coordinator.CompleteTask(ctx, plan, lease, success, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		at = at.Add(20 * time.Millisecond)
	}
	task, _ := plan.Task("context")
	lease, ok, err := coordinator.ClaimTask(ctx, plan, task.Key(), task.HandlerIdentity(), "worker", at)
	if err != nil || !ok {
		t.Fatal(err)
	}
	packet, err := coordinator.PrepareContextPacket(ctx, plan, lease, historicalDescriptor(plan, lease), at.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	facts, err := journal.InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 1 {
		t.Fatalf("facts=%d %v", len(facts), err)
	}
	fact := facts[0]
	ancestors := fact.TransitiveDependencySuccessEvents()
	keys := make([]string, len(ancestors))
	for i, event := range ancestors {
		keys[i] = event.TaskKey()
		if event.Sequence() >= packet.event.Sequence() || event.Attempt() != 1 || event.PlanIdentity() != plan.Identity() {
			t.Fatal("wrong captured success")
		}
	}
	if !slices.Equal(keys, []string{"analysis", "change", "memory", "source-base", "source-head"}) {
		t.Fatalf("ancestors=%v", keys)
	}
	direct := fact.UpstreamSuccessEvents()
	if len(direct) != 2 || direct[0].TaskKey() != "analysis" || direct[1].TaskKey() != "memory" {
		t.Fatal("direct accessor changed")
	}
	latest := make(map[string]RunEvent, len(ancestors)+1)
	for _, event := range ancestors {
		latest[event.TaskKey()] = event
	}
	latest["candidates"] = packet.event
	captured, err := historicalAncestorSuccesses(plan, task, packet.event, latest)
	if err != nil || len(captured) != 5 {
		t.Fatalf("captured=%d %v", len(captured), err)
	}
	prior := latest["source-base"]
	definition, _ := plan.Task(prior.TaskKey())
	retried, err := NewRunEvent(plan, prior.Sequence(), prior.PreviousIdentity(), RunEventTaskSucceeded, definition, 2, prior.LeaseTokenIdentity(), "", time.Time{}, strings.Repeat("f", 64), 0, time.Time{}, prior.OccurredAt())
	if err != nil {
		t.Fatal(err)
	}
	latest["source-base"] = retried
	next, err := historicalAncestorSuccesses(plan, task, packet.event, latest)
	if err != nil || next[3].Attempt() != 2 || next[3].Identity() != retried.Identity() || captured[3].Identity() != prior.Identity() {
		t.Fatal("latest success did not preserve independent capture or actual retry")
	}
	original := ancestors[0].Identity()
	ancestors[0].identity = "changed"
	if fact.TransitiveDependencySuccessEvents()[0].Identity() != original {
		t.Fatal("accessor aliases fact")
	}
	events, err := journal.Read(ctx, plan.Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := coordinator.Resume(ctx, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	for i := range events {
		if events[i].Kind() == RunEventTaskSucceeded && events[i].TaskKey() == "source-base" {
			events[i].outputIdentity = "malformed"
			break
		}
	}
	if _, _, err := historicalFactsForStream(plan, events, state, 1); !errors.Is(err, ErrInvalidStartupInventoryEntry) {
		t.Fatalf("malformed transitive success: %v", err)
	}
	if fact.TransitiveDependencySuccessEvents()[0].Identity() != original {
		t.Fatal("later event slice changed retained fact")
	}
}

func TestHistoricalPacketTransitiveSuccessPlanBound(t *testing.T) {
	tasks := []TaskDefinition{taskFixture(t, "source", TaskAcquireSource)}
	previous := "source"
	for i := 0; i < 61; i++ {
		key := fmt.Sprintf("change-%02d", i)
		tasks = append(tasks, taskFixture(t, key, TaskBuildChange, previous))
		previous = key
	}
	tasks = append(tasks, taskFixture(t, "context", TaskAssembleContext, previous), taskFixture(t, "candidates", TaskGenerateCandidates, "context"))
	plan, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunLocal, tasks)
	if err != nil || plan.TaskCount() != 64 {
		t.Fatalf("plan=%d %v", plan.TaskCount(), err)
	}
	ctx := context.Background()
	journal := NewMemoryRunJournal()
	coordinator, _ := NewCoordinator(journal)
	if _, err := coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	at := time.UnixMilli(200)
	keys := []string{"source"}
	for i := 0; i < 61; i++ {
		keys = append(keys, fmt.Sprintf("change-%02d", i))
	}
	for _, key := range keys {
		task, _ := plan.Task(key)
		lease, ok, err := coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", at)
		if err != nil || !ok {
			t.Fatalf("claim %s: %v", key, err)
		}
		success, _ := NewTaskSuccess(strings.Repeat("e", 64))
		if _, err := coordinator.CompleteTask(ctx, plan, lease, success, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		at = at.Add(20 * time.Millisecond)
	}
	task, _ := plan.Task("context")
	lease, ok, err := coordinator.ClaimTask(ctx, plan, task.Key(), task.HandlerIdentity(), "worker", at)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if _, err := coordinator.PrepareContextPacket(ctx, plan, lease, historicalDescriptor(plan, lease), at.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	events, err := journal.Read(ctx, plan.Scope(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := coordinator.Resume(ctx, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	facts, overflow, err := historicalFactsForStream(plan, events, state, 1)
	if err != nil || overflow || len(facts) != 1 || len(facts[0].TransitiveDependencySuccessEvents()) != 62 {
		t.Fatalf("bound facts=%d overflow=%v err=%v", len(facts), overflow, err)
	}
}

func TestHistoricalPacketTransitiveSuccessOptionalFailedAncestor(t *testing.T) {
	for _, failedRequired := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed-required-%t", failedRequired), func(t *testing.T) {
			ctx := context.Background()
			optional, err := NewTaskDefinition("optional", TaskInspectDeterministic, strings.Repeat("a", 64), strings.Repeat("d", 64), []string{"change"}, 3, 1000, 30000, false)
			if err != nil {
				t.Fatal(err)
			}
			tasks := []TaskDefinition{taskFixture(t, "source", TaskAcquireSource), taskFixture(t, "change", TaskBuildChange, "source"), optional,
				taskFixture(t, "analysis", TaskInspectDeterministic, "optional"), taskFixture(t, "context", TaskAssembleContext, "analysis")}
			plan, err := NewReviewRunPlan(runScopeFixture(t), strings.Repeat("b", 64), strings.Repeat("c", 64), ReviewRunLocal, tasks)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
			if err != nil {
				t.Fatal(err)
			}
			defer journal.Close()
			coordinator := inventoryOpen(t, journal, plan)
			at := time.UnixMilli(200)
			for _, key := range []string{"source", "change", "optional", "analysis"} {
				if failedRequired && key == "optional" {
					continue
				}
				task, _ := plan.Task(key)
				lease, ok, err := coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", at)
				if err != nil || !ok {
					t.Fatalf("claim %s: %v", key, err)
				}
				completion, _ := NewTaskSuccess(strings.Repeat("e", 64))
				if key == "optional" || failedRequired && key == "change" {
					completion, _ = NewTaskFailure(RunFailurePolicy)
				}
				if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, at.Add(time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				at = at.Add(20 * time.Millisecond)
			}
			task, _ := plan.Task("context")
			lease, ok, err := coordinator.ClaimTask(ctx, plan, task.Key(), task.HandlerIdentity(), "worker", at)
			if err != nil || !ok {
				t.Fatal(err)
			}
			if _, err := coordinator.PrepareContextPacket(ctx, plan, lease, historicalDescriptor(plan, lease), lease.ExpiresAt().Add(-2*time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			if _, _, err := coordinator.Resume(ctx, plan.Scope()); err != nil {
				t.Fatalf("valid replay rejected: %v", err)
			}
			facts, err := journal.InspectHistoricalContextPackets(ctx)
			if err != nil || len(facts) != 1 {
				t.Fatalf("valid optional history rejected: facts=%d err=%v", len(facts), err)
			}
			events := facts[0].TransitiveDependencySuccessEvents()
			keys := make([]string, len(events))
			for i, event := range events {
				keys[i] = event.TaskKey()
			}
			want := []string{"analysis", "change", "source"}
			if failedRequired {
				want = []string{"analysis", "source"}
			}
			if !slices.Equal(keys, want) || len(facts[0].UpstreamSuccessEvents()) != 1 {
				t.Fatalf("available ancestors=%v", keys)
			}

		})
	}
}
