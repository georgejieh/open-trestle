package controlplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var _ func(*FileRunJournal, context.Context) ([]HistoricalContextPacketFact, error) = (*FileRunJournal).InspectHistoricalContextPackets

func TestHistoricalPacketInventoryCanceledThenLateCorruption(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	plan := inventoryPlan(t, "old-tenant", "old-repo", "run-2")
	var later ReviewRunPlan
	for i := 0; i < 10000; i++ {
		candidate := inventoryPlan(t, "foreign-tenant", "foreign-repo", fmt.Sprintf("run-%d", i))
		if candidate.Scope().Identity() > plan.Scope().Identity() {
			later = candidate
			break
		}
	}
	if later.Scope().Identity() == "" {
		t.Fatal("no later foreign scope digest")
	}
	inventoryOpen(t, journal, later)
	coordinator := inventoryOpen(t, journal, plan)
	lease := inventoryPreparedLease(t, coordinator, plan)
	descriptor := ContextPacketDescriptor{
		LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(),
		PayloadDigest: strings.Repeat("b", 64), Classification: "internal", Protection: "process_private",
		Provenance:         []string{strings.Repeat("c", 64), strings.Repeat("e", 64)},
		SourceRootIdentity: strings.Repeat("d", 64), SnapshotIdentity: strings.Repeat("e", 64),
		DependencyIdentities:  []string{strings.Repeat("e", 64)},
		CreatedAtMilliseconds: 300, ExpiresAtMilliseconds: 3600300,
	}
	descriptor.ArtifactIdentity = packetArtifactIdentity(plan.Scope(), descriptor)
	prepared, err := coordinator.PrepareContextPacket(ctx, plan, lease, descriptor, lease.ExpiresAt().Add(-2*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	settled, err := coordinator.TerminatePreparedContextPacket(ctx, plan, prepared, lease.ExpiresAt().Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	canceled, err := coordinator.CancelRun(ctx, plan, lease.ExpiresAt().Add(2*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if settled.Status() != ReviewRunActive || canceled.Status() != ReviewRunCanceled {
		t.Fatalf("fixture status: settlement=%v final=%v", settled.Status(), canceled.Status())
	}
	events, err := journal.Read(ctx, plan.Scope(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	contextTask, ok := plan.Task("context")
	if !ok {
		t.Fatal("missing context task")
	}
	dependencies := contextTask.Dependencies()
	expectedUpstream := make([]RunEvent, 0, len(dependencies))
	for _, key := range dependencies {
		found := false
		for _, event := range events {
			if event.Kind() == RunEventTaskSucceeded && event.TaskKey() == key && event.Sequence() < prepared.event.Sequence() {
				expectedUpstream = append(expectedUpstream, event)
				found = true
			}
		}
		if !found {
			t.Fatalf("missing upstream success: %s", key)
		}
	}
	var expectedSettlement, expectedTerminal RunEvent
	for _, event := range events {
		if event.Kind() == RunEventTaskFailed && event.TaskKey() == "context" {
			expectedSettlement = event
		}
		if event.Kind() == RunEventCanceled {
			expectedTerminal = event
		}
	}
	if expectedSettlement.Identity() == "" || expectedTerminal.Identity() == "" {
		t.Fatal("missing settlement or terminal event")
	}
	if expectedSettlement.PreviousIdentity() != prepared.Identity() || expectedTerminal.PreviousIdentity() != expectedSettlement.Identity() {
		t.Fatal("fixture lacks direct prepared/settlement/canceled chain")
	}

	facts, err := journal.InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 1 {
		t.Fatalf("historical facts: count=%d err=%v", len(facts), err)
	}
	fact := facts[0]
	if fact.Plan().Identity() != plan.Identity() || fact.Plan().Scope().Identity() != plan.Scope().Identity() ||
		fact.Plan().Scope().TenantID() != "old-tenant" || fact.Plan().Scope().RepositoryID() != "old-repo" ||
		fact.Plan().Scope().ReviewRunID() != "run-2" || !reflect.DeepEqual(fact.Plan().Tasks(), plan.Tasks()) {
		t.Fatal("fact plan or scope differs")
	}
	event := fact.PreparedEvent()
	if event.Kind() != RunEventContextPacketPrepared || event.Identity() != prepared.Identity() ||
		event.PlanIdentity() != plan.Identity() || event.Scope().Identity() != plan.Scope().Identity() ||
		event.Sequence() != prepared.event.Sequence() || event.PreviousIdentity() != prepared.event.PreviousIdentity() ||
		event.TaskKey() != "context" || event.TaskIdentity() != contextTask.Identity() ||
		event.Attempt() != prepared.event.Attempt() || event.LeaseTokenIdentity() != prepared.event.LeaseTokenIdentity() ||
		event.OutputIdentity() != descriptor.ArtifactIdentity || !event.OccurredAt().Equal(prepared.event.OccurredAt()) ||
		!reflect.DeepEqual(event.PacketDescriptor(), descriptor) {
		t.Fatal("prepared event or packet descriptor differs")
	}
	upstream := fact.UpstreamSuccessEvents()
	if len(upstream) == 0 || !reflect.DeepEqual(upstream, expectedUpstream) {
		t.Fatal("upstream success event evidence differs")
	}
	if linked, ok := fact.LinkedInputEvent(); ok {
		t.Fatalf("unexpected linked input: %s", linked.Identity())
	}
	settlement, ok := fact.TaskSettlementEvent()
	if !ok || settlement.Identity() != expectedSettlement.Identity() || settlement.Sequence() != expectedSettlement.Sequence() || settlement.Failure() != RunFailurePolicy {
		t.Fatal("task settlement not linked to this preparation")
	}
	terminal, ok := fact.TerminalEvent()
	if !ok || terminal.Identity() != expectedTerminal.Identity() || terminal.Kind() != RunEventCanceled {
		t.Fatal("missing canceled terminal event")
	}
	if fact.FinalRunStatus() != ReviewRunCanceled || fact.FinalRevision() != canceled.Revision() ||
		fact.FinalHeadIdentity() != canceled.HeadIdentity() || fact.FinalHeadIdentity() != terminal.Identity() {
		t.Fatal("historical fact did not retain complete replay final status/head")
	}
	upstream[0] = RunEvent{}
	modified := event.PacketDescriptor()
	modified.Provenance[0] = strings.Repeat("f", 64)
	modified.DependencyIdentities[0] = strings.Repeat("f", 64)
	facts[0] = HistoricalContextPacketFact{}
	again, err := journal.InspectHistoricalContextPackets(ctx)
	if err != nil || len(again) != 1 || again[0].PreparedEvent().Identity() != prepared.Identity() ||
		!reflect.DeepEqual(again[0].PreparedEvent().PacketDescriptor(), descriptor) ||
		!reflect.DeepEqual(again[0].UpstreamSuccessEvents(), expectedUpstream) {
		t.Fatalf("historical facts not independently readable: count=%d err=%v", len(again), err)
	}
	inventory, err := journal.InspectStartupInventory(ctx)
	if !errors.Is(err, ErrPreparedContextPacketAtStartup) || inventory != (StartupInventory{}) {
		t.Fatalf("startup blanket verdict: %+v %v", inventory, err)
	}
	if err := os.WriteFile(journal.streamPath(later.Scope()), []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	facts, err = journal.InspectHistoricalContextPackets(ctx)
	if facts != nil || !errors.Is(err, ErrCorruptRunJournalStream) || errors.Is(err, ErrPreparedContextPacketAtStartup) {
		t.Fatalf("late corruption must discard all facts: count=%d nil=%v err=%v", len(facts), facts == nil, err)
	}
	inventory, err = journal.InspectStartupInventory(ctx)
	if inventory != (StartupInventory{}) || !errors.Is(err, ErrCorruptRunJournalStream) {
		t.Fatalf("startup corruption precedence: %+v %v", inventory, err)
	}
}
