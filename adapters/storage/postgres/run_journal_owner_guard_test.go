package postgres

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

// ownerGuardStreams builds, through the public coordinator on the memory journal, a run whose
// "context" lease has claimed (beforePacket) and then recorded a prepared packet checkpoint
// (afterPacket), plus a public success event for that same lease that follows the checkpoint.
func ownerGuardStreams(t *testing.T) (plan controlplane.ReviewRunPlan, beforePacket, afterPacket []controlplane.RunEvent, success controlplane.RunEvent) {
	t.Helper()
	ctx := context.Background()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-owner-guard")
	if err != nil {
		t.Fatal(err)
	}
	specs := []struct {
		key          string
		kind         controlplane.TaskKind
		dependencies []string
	}{
		{"source", controlplane.TaskAcquireSource, nil}, {"change", controlplane.TaskBuildChange, []string{"source"}},
		{"analysis", controlplane.TaskInspectDeterministic, []string{"change"}}, {"memory", controlplane.TaskRetrieveContext, []string{"change"}},
		{"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}},
		{"candidates", controlplane.TaskGenerateCandidates, []string{"context"}}, {"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}},
		{"readiness", controlplane.TaskEvaluatePublication, []string{"verification"}}, {"publication", controlplane.TaskPublishResult, []string{"readiness"}},
	}
	definitions := make([]controlplane.TaskDefinition, 0, len(specs))
	for _, spec := range specs {
		attempts := uint8(3)
		if spec.key == "publication" {
			attempts = 1
		}
		definition, err := controlplane.NewTaskDefinition(spec.key, spec.kind, strings.Repeat("a", 64), strings.Repeat("d", 64), spec.dependencies, attempts, 1000, 30000, true)
		if err != nil {
			t.Fatal(err)
		}
		definitions = append(definitions, definition)
	}
	plan, err = controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunRequired, definitions)
	if err != nil {
		t.Fatal(err)
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	at := int64(200)
	for _, key := range []string{"source", "change", "analysis", "memory"} {
		task, _ := plan.Task(key)
		lease, ok, err := coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", time.UnixMilli(at))
		if err != nil || !ok {
			t.Fatalf("claim %s: %v", key, err)
		}
		done, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
		if _, err := coordinator.CompleteTask(ctx, plan, lease, done, time.UnixMilli(at+1)); err != nil {
			t.Fatal(err)
		}
		at += 20
	}
	task, _ := plan.Task("context")
	lease, ok, err := coordinator.ClaimTask(ctx, plan, "context", task.HandlerIdentity(), "worker", time.UnixMilli(at))
	if err != nil || !ok {
		t.Fatalf("claim context: %v", err)
	}
	beforePacket, err = journal.Read(ctx, scope, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationInternal, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{strings.Repeat("e", 64)}, []byte(`{"packet":"fixture"}`), time.UnixMilli(at+10), time.UnixMilli(at+3_600_000))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := coordinator.PrepareContextPacket(ctx, plan, lease, controlplane.ContextPacketDescriptor{
		ArtifactIdentity: packet.Identity(), LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(),
		PayloadDigest: packet.PayloadDigest(), Classification: packet.Classification().String(), Protection: packet.Protection().String(),
		Provenance: packet.Provenance(), SourceRootIdentity: strings.Repeat("a", 64), SnapshotIdentity: strings.Repeat("b", 64),
		DependencyIdentities:  []string{strings.Repeat("e", 64)},
		CreatedAtMilliseconds: packet.CreatedAt().UnixMilli(), ExpiresAtMilliseconds: packet.ExpiresAt().UnixMilli(),
	}, time.UnixMilli(at+11))
	if err != nil {
		t.Fatal(err)
	}
	afterPacket, err = journal.Read(ctx, scope, 0, 1000)
	if err != nil || len(afterPacket) != len(beforePacket)+1 || afterPacket[len(afterPacket)-1].Identity() != prepared.Identity() {
		t.Fatalf("prepared stream: events=%d before=%d err=%v", len(afterPacket), len(beforePacket), err)
	}
	token := ""
	for _, event := range beforePacket {
		if event.TaskKey() == "context" && event.LeaseTokenIdentity() != "" {
			token = event.LeaseTokenIdentity()
		}
	}
	head := afterPacket[len(afterPacket)-1]
	success, err = controlplane.NewRunEvent(plan, head.Sequence()+1, head.Identity(), controlplane.RunEventTaskSucceeded, task,
		lease.Attempt(), token, "", time.Time{}, packet.Identity(), 0, time.Time{}, lease.ExpiresAt().Add(-time.Millisecond))
	if err != nil {
		t.Fatalf("public success: %v", err)
	}
	return plan, beforePacket, afterPacket, success
}

func expectOwnerGuardAppendPrefix(t *testing.T, mock sqlmock.Sqlmock, scope audit.ReviewScope, history []controlplane.RunEvent, planIdentity string) {
	t.Helper()
	expectTenantTransaction(mock, scope.TenantID())
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs(scope.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
	expectScope(mock, scope)
	mock.ExpectQuery("SELECT plan_identity").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).
		WillReturnRows(sqlmock.NewRows([]string{"plan_identity"}).AddRow(planIdentity))
	rows := sqlmock.NewRows([]string{"sequence", "event_identity", "canonical_event"})
	for _, event := range history {
		encoded, err := controlplane.EncodeRunEvent(event)
		if err != nil {
			t.Fatal(err)
		}
		rows.AddRow(event.Sequence(), event.Identity(), encoded)
	}
	mock.ExpectQuery(`sequence < \$4`).WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), uint64(len(history))+1).WillReturnRows(rows)
}

func TestPostgresRunJournalRefusesPublicSuccessAfterPreparedContextPacket(t *testing.T) {
	plan, _, afterPacket, success := ownerGuardStreams(t)
	scope := plan.Scope()
	database, mock := newMockDatabase(t)
	store, _ := New(database)
	expectOwnerGuardAppendPrefix(t, mock, scope, afterPacket, plan.Identity())
	mock.ExpectRollback()
	err := store.Append(context.Background(), afterPacket[len(afterPacket)-1].Identity(), success)
	if !errors.Is(err, controlplane.ErrPreparedContextPacket) {
		t.Fatalf("append=%v, want ErrPreparedContextPacket", err)
	}
	assertMock(t, mock)
}

func TestPostgresRunJournalAllowsPublicSuccessWithoutPreparedPacket(t *testing.T) {
	plan, beforePacket, _, success := ownerGuardStreams(t)
	scope := plan.Scope()
	// Same lease and sequence number, but the checkpoint was never recorded in this stream.
	head := beforePacket[len(beforePacket)-1]
	task, _ := plan.Task("context")
	token := head.LeaseTokenIdentity()
	direct, err := controlplane.NewRunEvent(plan, head.Sequence()+1, head.Identity(), controlplane.RunEventTaskSucceeded, task,
		head.Attempt(), token, "", time.Time{}, success.OutputIdentity(), 0, time.Time{}, success.OccurredAt())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := controlplane.EncodeRunEvent(direct)
	headEncoded, _ := controlplane.EncodeRunEvent(head)
	database, mock := newMockDatabase(t)
	store, _ := New(database)
	expectOwnerGuardAppendPrefix(t, mock, scope, beforePacket, plan.Identity())
	mock.ExpectQuery("ORDER BY sequence DESC LIMIT 1").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).
		WillReturnRows(sqlmock.NewRows([]string{"sequence", "event_identity", "canonical_event", "count"}).AddRow(head.Sequence(), head.Identity(), headEncoded, head.Sequence()))
	mock.ExpectExec("INSERT INTO open_trestle_run_events").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), direct.PlanIdentity(), direct.Sequence(), direct.Identity(), direct.PreviousIdentity(), encoded, direct.OccurredAt()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	if err := store.Append(context.Background(), head.Identity(), direct); err != nil {
		t.Fatalf("append without checkpoint=%v", err)
	}
	assertMock(t, mock)
}
