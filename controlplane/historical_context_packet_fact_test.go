package controlplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

func historicalDescriptor(plan ReviewRunPlan, lease TaskLease) ContextPacketDescriptor {
	d := ContextPacketDescriptor{
		LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(),
		PayloadDigest: strings.Repeat("b", 64), Classification: "internal", Protection: "process_private",
		Provenance:         []string{strings.Repeat("c", 64), strings.Repeat("e", 64)},
		SourceRootIdentity: strings.Repeat("d", 64), SnapshotIdentity: strings.Repeat("e", 64),
		DependencyIdentities:  []string{strings.Repeat("e", 64)},
		CreatedAtMilliseconds: 300, ExpiresAtMilliseconds: 3600300,
	}
	d.ArtifactIdentity = packetArtifactIdentity(plan.Scope(), d)
	return d
}

func TestHistoricalPacketInventoryTwoScopesTwoContextsAndIsolation(t *testing.T) {
	ctx := context.Background()
	j, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	a := inventoryPlan(t, "tenant-a", "repo-a", "run-a")
	b := inventoryPlan(t, "tenant-b", "repo-b", "run-b")
	// Add another independent context, with a unique highest-kind result task
	// already supplied by the original plan graph.
	tasks := runPlanTasks(t)
	tasks = append(tasks, taskFixture(t, "context-b", TaskAssembleContext, "analysis", "memory"))
	a, err = NewReviewRunPlan(a.Scope(), a.RequestIdentity(), a.PolicyIdentity(), a.Mode(), tasks)
	if err != nil {
		t.Fatal(err)
	}
	first, second := a, b
	if first.Scope().Identity() < second.Scope().Identity() {
		first, second = second, first
	}
	// Insert reverse digest order to prove sorted output is not insertion order.
	for _, plan := range []ReviewRunPlan{first, second} {
		c := inventoryOpen(t, j, plan)
		lease := inventoryPreparedLease(t, c, plan)
		packet, err := c.PrepareContextPacket(ctx, plan, lease, historicalDescriptor(plan, lease), lease.ExpiresAt().Add(-2*time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.TerminatePreparedContextPacket(ctx, plan, packet, lease.ExpiresAt().Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		if plan.Identity() == a.Identity() {
			task, _ := plan.Task("context-b")
			next, ok, err := c.ClaimTask(ctx, plan, task.Key(), task.HandlerIdentity(), "worker", lease.ExpiresAt().Add(2*time.Millisecond))
			if err != nil || !ok {
				t.Fatalf("second context claim: %v %v", ok, err)
			}
			secondPacket, err := c.PrepareContextPacket(ctx, plan, next, historicalDescriptor(plan, next), next.ExpiresAt().Add(-2*time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			if secondPacket.Identity() == packet.Identity() {
				t.Fatal("same v4 identity")
			}
			if _, err := c.CancelRun(ctx, plan, next.ExpiresAt().Add(time.Millisecond)); err != nil {
				t.Fatal(err)
			}
		}
	}
	facts, err := j.InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 3 {
		t.Fatalf("facts: %d %v", len(facts), err)
	}
	for i := 1; i < len(facts); i++ {
		previous, current := facts[i-1], facts[i]
		if previous.Plan().Scope().Identity() > current.Plan().Scope().Identity() ||
			(previous.Plan().Scope().Identity() == current.Plan().Scope().Identity() && previous.PreparedEvent().Sequence() >= current.PreparedEvent().Sequence()) {
			t.Fatal("facts not sorted by digest and sequence")
		}
	}
	aCount := 0
	for _, fact := range facts {
		if fact.Plan().Identity() != a.Identity() {
			continue
		}
		aCount++
		if fact.FinalRunStatus() != ReviewRunCanceled {
			t.Fatal("wrong final status")
		}
		if fact.PreparedEvent().TaskKey() == "context" {
			if _, ok := fact.TaskSettlementEvent(); !ok {
				t.Fatal("first packet not settled")
			}
		} else if _, ok := fact.TaskSettlementEvent(); ok {
			t.Fatal("second packet falsely settled")
		}
		if terminal, ok := fact.TerminalEvent(); !ok || terminal.Kind() != RunEventCanceled {
			t.Fatal("missing terminal")
		}
	}
	if aCount != 2 {
		t.Fatalf("expected two context facts, got %d", aCount)
	}
	for _, fact := range facts {
		p := fact.Plan()
		p.tasks[0].dependencies = []string{"broken"}
		for _, task := range p.tasks {
			if len(task.dependencies) > 0 {
				task.dependencies[0] = "broken"
				break
			}
		}
		event := fact.PreparedEvent()
		event.packetDescriptor.Provenance[0] = "broken"
		event.packetDescriptor.DependencyIdentities[0] = "broken"
		upstream := fact.UpstreamSuccessEvents()
		upstream[0] = RunEvent{}
		if fact.PreparedEvent().PacketDescriptor().Provenance[0] == "broken" || fact.UpstreamSuccessEvents()[0].Identity() == "" {
			t.Fatal("event accessor aliases")
		}
		if plan := fact.Plan(); plan.Validate() != nil {
			t.Fatalf("plan accessor aliases: %v", plan.Validate())
		}
	}
	old, err := j.InspectStartupInventory(ctx)
	if old != (StartupInventory{}) || !errors.Is(err, ErrPreparedContextPacketAtStartup) {
		t.Fatalf("old verdict: %+v %v", old, err)
	}
}

func TestHistoricalPacketInventoryEmptyAndPrecedence(t *testing.T) {
	ctx := context.Background()
	j, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	empty, err := j.InspectHistoricalContextPackets(ctx)
	if err != nil || len(empty) != 0 {
		t.Fatalf("valid empty: %d %v", len(empty), err)
	}
	plan := inventoryPlan(t, "tenant", "repo", "run")
	inventoryOpen(t, j, plan)
	empty, err = j.InspectHistoricalContextPackets(ctx)
	if err != nil || len(empty) != 0 {
		t.Fatalf("valid no-v4: %d %v", len(empty), err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	facts, err := j.InspectHistoricalContextPackets(canceled)
	if facts != nil || !errors.Is(err, ErrRunJournalContextDone) {
		t.Fatalf("cancel: %v %v", facts, err)
	}
	if err := os.Remove(j.streamPath(plan.Scope())); err != nil {
		t.Fatal(err)
	}
	facts, err = j.InspectHistoricalContextPackets(ctx)
	if facts != nil || !errors.Is(err, ErrIncompleteStartupInventoryPrefix) {
		t.Fatalf("missing stream: %v %v", facts, err)
	}
	if err := os.WriteFile(j.planPath(plan.Scope()), []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	facts, err = j.InspectHistoricalContextPackets(ctx)
	if facts != nil || !errors.Is(err, ErrInvalidReviewRunPlanEncoding) {
		t.Fatalf("invalid plan: %v %v", facts, err)
	}
}

func TestHistoricalPacketInventoryLinkedV5AndNestedClones(t *testing.T) {
	ctx := context.Background()
	j, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	plan := inventoryPlan(t, "tenant", "repo", "run")
	c := inventoryOpen(t, j, plan)
	lease := inventoryPreparedLease(t, c, plan)
	d := historicalDescriptor(plan, lease)
	packetAt := lease.ExpiresAt().Add(-10 * time.Millisecond)
	packet, err := c.PrepareContextPacket(ctx, plan, lease, d, packetAt)
	if err != nil {
		t.Fatal(err)
	}
	makeObject := func(kind string, provenance []string) ContextInputArtifactDescriptor {
		slices.Sort(provenance)
		value := ContextInputArtifactDescriptor{
			PayloadDigest: strings.Repeat("2", 64), Classification: d.Classification, Protection: d.Protection,
			Provenance: provenance, CreatedAtMilliseconds: packetAt.Add(time.Millisecond).UnixMilli(),
			ExpiresAtMilliseconds: d.ExpiresAtMilliseconds,
		}
		value.ArtifactIdentity = contextInputArtifactIdentity(plan.Scope(), kind, value)
		return value
	}
	authorization := strings.Repeat("8", 64)
	request := makeObject("sanitized_model_request", []string{d.ArtifactIdentity})
	receipt := makeObject("sanitized_egress_receipt", []string{d.ArtifactIdentity, request.ArtifactIdentity})
	input := makeObject("task_input", []string{d.ArtifactIdentity, request.ArtifactIdentity, receipt.ArtifactIdentity, authorization})
	id := ContextInputDescriptor{
		PacketPreparedEventIdentity: packet.Identity(), PacketArtifactIdentity: d.ArtifactIdentity,
		LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(),
		Request: request, Receipt: receipt, Input: input,
		ReceiptIdentity: strings.Repeat("4", 64), ScannerLauncherDigest: strings.Repeat("5", 64),
		ScannerWorkerDigest: strings.Repeat("6", 64), GenerationInputIdentity: strings.Repeat("7", 64),
		AuthorizationIdentity: authorization, SelectionReceiptIdentity: strings.Repeat("9", 64),
		RoutingInputIdentity: strings.Repeat("a", 64), SelectedRecordIdentity: strings.Repeat("b", 64),
		PolicyIdentity: strings.Repeat("d", 64), RoutePairIdentity: strings.Repeat("e", 64),
		AuthorizerIdentity: strings.Repeat("f", 64), SanitizerIdentity: strings.Repeat("1", 64),
		RegistryRevision: 11, PerformanceRevision: 5,
	}
	inputPrepared, err := c.PrepareContextInput(ctx, plan, lease, packet, id, packetAt.Add(2*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.TerminatePreparedContextInput(ctx, plan, inputPrepared, lease.ExpiresAt().Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	facts, err := j.InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 1 {
		t.Fatalf("linked facts: %d %v", len(facts), err)
	}
	linked, ok := facts[0].LinkedInputEvent()
	if !ok || linked.Identity() != inputPrepared.Identity() || linked.InputDescriptor().PacketPreparedEventIdentity != packet.Identity() {
		t.Fatal("wrong v5 linkage")
	}
	if settled, ok := facts[0].TaskSettlementEvent(); !ok || settled.Kind() != RunEventTaskFailed || settled.Sequence() <= linked.Sequence() {
		t.Fatal("missing v5 settlement")
	}
	linked.inputDescriptor.Request.Provenance[0] = "broken"
	linked.inputDescriptor.Receipt.Provenance[0] = "broken"
	linked.inputDescriptor.Input.Provenance[0] = "broken"
	again, _ := facts[0].LinkedInputEvent()
	if again.InputDescriptor().Request.Provenance[0] == "broken" || again.InputDescriptor().Receipt.Provenance[0] == "broken" || again.InputDescriptor().Input.Provenance[0] == "broken" {
		t.Fatal("v5 nested descriptor aliases retained fact")
	}
}

func TestHistoricalPacketInventoryUpstreamRetryBeforeSuccess(t *testing.T) {
	ctx := context.Background()
	j, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	plan := inventoryPlan(t, "tenant", "repo", "retry")
	c := inventoryOpen(t, j, plan)
	for i, key := range []string{"source", "change"} {
		task, _ := plan.Task(key)
		at := time.UnixMilli(int64(200 + 20*i))
		lease, ok, err := c.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", at)
		if err != nil || !ok {
			t.Fatalf("claim %s: %v", key, err)
		}
		success, _ := NewTaskSuccess(strings.Repeat("e", 64))
		if _, err := c.CompleteTask(ctx, plan, lease, success, at.Add(time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	analysis, _ := plan.Task("analysis")
	first, ok, err := c.ClaimTask(ctx, plan, "analysis", analysis.HandlerIdentity(), "worker", time.UnixMilli(240))
	if err != nil || !ok {
		t.Fatal(err)
	}
	failure, _ := NewTaskFailure(RunFailureTransient)
	failed, err := c.CompleteTask(ctx, plan, first, failure, time.UnixMilli(241))
	if err != nil {
		t.Fatal(err)
	}
	failedRuntime, _ := failed.Task("analysis")
	retryAt := failedRuntime.RetryAt()
	if _, err := c.Advance(ctx, plan, retryAt); err != nil {
		t.Fatal(err)
	}
	second, ok, err := c.ClaimTask(ctx, plan, "analysis", analysis.HandlerIdentity(), "worker", retryAt.Add(time.Millisecond))
	if err != nil || !ok {
		t.Fatalf("retry claim: %v", err)
	}
	success, _ := NewTaskSuccess(strings.Repeat("e", 64))
	if _, err := c.CompleteTask(ctx, plan, second, success, retryAt.Add(2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	memory, _ := plan.Task("memory")
	third, ok, err := c.ClaimTask(ctx, plan, "memory", memory.HandlerIdentity(), "worker", retryAt.Add(3*time.Millisecond))
	if err != nil || !ok {
		t.Fatalf("memory claim: %v", err)
	}
	if _, err := c.CompleteTask(ctx, plan, third, success, retryAt.Add(4*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	contextTask, _ := plan.Task("context")
	lease, ok, err := c.ClaimTask(ctx, plan, "context", contextTask.HandlerIdentity(), "worker", retryAt.Add(5*time.Millisecond))
	if err != nil || !ok {
		t.Fatalf("context claim: %v", err)
	}
	packet, err := c.PrepareContextPacket(ctx, plan, lease, historicalDescriptor(plan, lease), retryAt.Add(6*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	facts, err := j.InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 1 {
		t.Fatalf("retry facts: %d %v", len(facts), err)
	}
	events, err := j.Read(ctx, plan.Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var laterSuccess RunEvent
	for _, event := range events {
		if event.Kind() == RunEventTaskSucceeded && event.TaskKey() == "analysis" {
			laterSuccess = event
		}
	}
	upstream := facts[0].UpstreamSuccessEvents()
	if len(upstream) != 2 || upstream[0].Identity() != laterSuccess.Identity() ||
		upstream[0].Attempt() != 2 || upstream[0].Sequence() >= packet.event.Sequence() ||
		upstream[0].TaskIdentity() != analysis.Identity() || upstream[0].OutputIdentity() != strings.Repeat("e", 64) {
		t.Fatal("upstream did not retain actual post-retry success")
	}
}

func TestHistoricalPacketInventoryFactBoundaryAndLateCorruption(t *testing.T) {
	ctx := context.Background()
	j, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	makePlan := func(run string) ReviewRunPlan {
		base := inventoryPlan(t, "tenant", "repo", run)
		tasks := []TaskDefinition{
			taskFixture(t, "source", TaskAcquireSource),
			taskFixture(t, "change", TaskBuildChange, "source"),
		}
		for n := 0; n < 4; n++ {
			tasks = append(tasks, taskFixture(t, fmt.Sprintf("context-%02d", n), TaskAssembleContext, "change"))
		}
		tasks = append(tasks, taskFixture(t, "candidates", TaskGenerateCandidates, "context-00"))
		plan, err := NewReviewRunPlan(base.Scope(), base.RequestIdentity(), base.PolicyIdentity(), base.Mode(), tasks)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	plans := make([]ReviewRunPlan, 257)
	for i := range plans {
		plans[i] = makePlan(fmt.Sprintf("run-%d", i))
	}
	sort.Slice(plans, func(i, j int) bool { return plans[i].Scope().Identity() < plans[j].Scope().Identity() })
	openWithFacts := func(plan ReviewRunPlan, count int) {
		c := inventoryOpen(t, j, plan)
		for n, key := range []string{"source", "change"} {
			task, _ := plan.Task(key)
			at := time.UnixMilli(int64(200 + 20*n))
			lease, ok, err := c.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", at)
			if err != nil || !ok {
				t.Fatalf("base claim: %v", err)
			}
			success, _ := NewTaskSuccess(strings.Repeat("e", 64))
			if _, err := c.CompleteTask(ctx, plan, lease, success, at.Add(time.Millisecond)); err != nil {
				t.Fatal(err)
			}
		}
		at := time.UnixMilli(240)
		for n := 0; n < count; n++ {
			key := fmt.Sprintf("context-%02d", n)
			task, _ := plan.Task(key)
			lease, ok, err := c.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", at)
			if err != nil || !ok {
				t.Fatalf("claim %s: %v %v", key, ok, err)
			}
			prepared, err := c.PrepareContextPacket(ctx, plan, lease, historicalDescriptor(plan, lease), lease.ExpiresAt().Add(-2*time.Millisecond))
			if err != nil {
				t.Fatalf("prepare %s: %v", key, err)
			}
			at = lease.ExpiresAt().Add(time.Millisecond)
			if _, err := c.TerminatePreparedContextPacket(ctx, plan, prepared, at); err != nil {
				t.Fatalf("settle %s: %v", key, err)
			}
			at = at.Add(time.Millisecond)
		}
	}
	// 256 small independent plans remain below the 500-plan and 1024-entry
	// old ceilings. Four v4s each reach exactly the new diagnostic ceiling.
	for _, plan := range plans[:256] {
		openWithFacts(plan, 4)
	}
	facts, err := j.InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 1024 {
		t.Fatalf("at 1024: %d %v", len(facts), err)
	}
	openWithFacts(plans[256], 1)
	facts, err = j.InspectHistoricalContextPackets(ctx)
	if facts != nil || !errors.Is(err, ErrStartupInventoryLimit) {
		t.Fatalf("at 1025: %d nil=%v %v", len(facts), facts == nil, err)
	}
	var later ReviewRunPlan
	for i := 257; i < 10000; i++ {
		candidate := inventoryPlan(t, "foreign", "repo", fmt.Sprintf("run-%d", i))
		if candidate.Scope().Identity() > plans[256].Scope().Identity() {
			later = candidate
			break
		}
	}
	if later.Scope().Identity() == "" {
		t.Fatal("no later digest")
	}
	inventoryOpen(t, j, later)
	if err := os.WriteFile(j.streamPath(later.Scope()), []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	facts, err = j.InspectHistoricalContextPackets(ctx)
	if facts != nil || !errors.Is(err, ErrCorruptRunJournalStream) {
		t.Fatalf("later corruption: %d nil=%v %v", len(facts), facts == nil, err)
	}
}
