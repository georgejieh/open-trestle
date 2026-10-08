package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPreparedContextAbstentionRequiresDurableIntent(t *testing.T) {
	plan := runPlanFixture(t)
	coordinator, _ := NewCoordinator(NewMemoryRunJournal())
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	var lease TaskLease
	_, err := coordinator.PrepareContextAbstention(context.Background(), plan, lease, nil, RunFailurePolicy, time.UnixMilli(200))
	if err == nil {
		t.Fatal("invalid lease and artifact accepted")
	}
	if _, ok := (TaskRuntimeState{}).PreparedContextAbstention(); ok {
		t.Fatal("zero state has prepared descriptor")
	}
}

func preparedTestArtifact(t *testing.T, plan ReviewRunPlan, payload []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(payload)
	r := preparedArtifactRecord{Contract: "open-trestle/runtime-artifact", SchemaVersion: 1, TenantID: plan.Scope().TenantID(), RepositoryID: plan.Scope().RepositoryID(), ReviewRunID: plan.Scope().ReviewRunID(), Kind: "deterministic_evidence", MediaType: "application/json", Classification: "internal", Origin: "deterministic_tool", Protection: "process_private", Provenance: []string{strings.Repeat("a", 64)}, PayloadDigest: hex.EncodeToString(digest[:]), Payload: payload, CreatedAtMilliseconds: 100, ExpiresAtMilliseconds: 3600100}
	preimage := struct {
		ScopeIdentity         string   `json:"scope_identity"`
		Kind                  string   `json:"kind"`
		MediaType             string   `json:"media_type"`
		Classification        string   `json:"classification"`
		Origin                string   `json:"origin"`
		Protection            string   `json:"protection"`
		Provenance            []string `json:"provenance"`
		PayloadDigest         string   `json:"payload_digest"`
		CreatedAtMilliseconds int64    `json:"created_at_milliseconds"`
		ExpiresAtMilliseconds int64    `json:"expires_at_milliseconds"`
	}{plan.Scope().Identity(), r.Kind, r.MediaType, r.Classification, r.Origin, r.Protection, r.Provenance, r.PayloadDigest, r.CreatedAtMilliseconds, r.ExpiresAtMilliseconds}
	value, _ := json.Marshal(preimage)
	identity := sha256.Sum256(value)
	r.Identity = hex.EncodeToString(identity[:])
	encoded, _ := json.Marshal(r)
	return encoded
}
func preparedTestLease(t *testing.T, journal RunJournal) (*Coordinator, ReviewRunPlan, TaskLease) {
	t.Helper()
	coordinator, _ := NewCoordinator(journal)
	plan := runPlanFixture(t)
	ctx := context.Background()
	if _, err := coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	at := int64(200)
	for _, key := range []string{"source", "change", "analysis", "memory"} {
		task, _ := plan.Task(key)
		lease, ok, err := coordinator.ClaimTask(ctx, plan, key, task.HandlerIdentity(), "worker", time.UnixMilli(at))
		if err != nil || !ok {
			t.Fatalf("claim %s %v", key, err)
		}
		success, _ := NewTaskSuccess(strings.Repeat("e", 64))
		if _, err = coordinator.CompleteTask(ctx, plan, lease, success, time.UnixMilli(at+1)); err != nil {
			t.Fatal(err)
		}
		at += 20
	}
	task, _ := plan.Task("context")
	lease, ok, err := coordinator.ClaimTask(ctx, plan, "context", task.HandlerIdentity(), "worker", time.UnixMilli(at))
	if err != nil || !ok {
		t.Fatal(err)
	}
	return coordinator, plan, lease
}
func TestPreparedIntentCrashBoundariesAndRecovery(t *testing.T) {
	for _, failure := range []RunFailure{RunFailurePolicy, RunFailureResourceLimit} {
		t.Run(failure.String(), func(t *testing.T) {
			ctx := context.Background()
			journal := NewMemoryRunJournal()
			coordinator, plan, lease := preparedTestLease(t, journal)
			artifact := preparedTestArtifact(t, plan, []byte(`{"reason":"content-free"}`))
			before := lease.ExpiresAt().Add(-time.Millisecond)
			prepared, err := coordinator.PrepareContextAbstention(ctx, plan, lease, artifact, failure, before)
			if err != nil {
				t.Fatal(err)
			}
			artifact[0] = 'X'
			if prepared.EncodedArtifact()[0] != '{' {
				t.Fatal("prepared bytes mutated by caller")
			}
			copied := prepared.EncodedArtifact()
			copied[0] = 'X'
			if prepared.EncodedArtifact()[0] != '{' {
				t.Fatal("descriptor leaked mutable bytes")
			}
			eventWire, err := EncodeRunEvent(prepared.event)
			if err != nil || !bytes.Contains(eventWire, []byte(`"schema_version":3`)) || !bytes.Contains(eventWire, []byte(`"prepared_artifact":`)) {
				t.Fatalf("v3: %v", err)
			}
			parsed, err := ParseRunEvent(eventWire)
			if err != nil || parsed.Identity() != prepared.Identity() {
				t.Fatalf("v3 parse: %v", err)
			}
			restarted, _ := NewCoordinator(journal)
			_, state, err := restarted.Resume(ctx, plan.Scope())
			if err != nil {
				t.Fatal(err)
			}
			runtime, _ := state.Task("context")
			restored, ok := runtime.PreparedContextAbstention()
			if !ok || restored.Identity() != prepared.Identity() || restored.ArtifactIdentity() == "" || restored.Failure() != failure || runtime.Status() != TaskRuntimeLeased {
				t.Fatal("intent not recoverable")
			}
			expired := lease.ExpiresAt().Add(time.Millisecond)
			state, err = restarted.Advance(ctx, plan, expired)
			if err != nil {
				t.Fatal(err)
			}
			runtime, _ = state.Task("context")
			if runtime.Status() != TaskRuntimeLeased || runtime.OutputIdentity() != "" {
				t.Fatal("generic expiry replaced intent")
			}
			if _, claimed, err := restarted.ClaimTask(ctx, plan, "context", runtime.Definition().HandlerIdentity(), "other", expired); err != nil || claimed {
				t.Fatalf("expired prepared lease reclaimed %v", err)
			}
			empty, _ := NewTaskFailure(RunFailureResourceLimit)
			if _, err := restarted.CompleteTask(ctx, plan, lease, empty, before); !errors.Is(err, ErrPreparedContextAbstention) {
				t.Fatalf("empty completion accepted: %v", err)
			}
			state, err = restarted.SettlePreparedContextAbstention(ctx, plan, restored, expired)
			if err != nil {
				t.Fatal(err)
			}
			runtime, _ = state.Task("context")
			if runtime.Status() != TaskRuntimeFailed || runtime.OutputIdentity() != restored.ArtifactIdentity() || runtime.Failure() != failure {
				t.Fatal("settlement mismatch")
			}
			if next, _ := state.Task("candidates"); next.Status() != TaskRuntimePending {
				t.Fatal("generation became available")
			}
			duplicate, err := restarted.SettlePreparedContextAbstention(ctx, plan, restored, expired.Add(time.Millisecond))
			if err != nil || duplicate.HeadIdentity() != state.HeadIdentity() {
				t.Fatalf("duplicate settlement %v", err)
			}
		})
	}
}
func TestPreparedIntentRejectsForeignAndMalformedArtifacts(t *testing.T) {
	ctx := context.Background()
	coordinator, plan, lease := preparedTestLease(t, NewMemoryRunJournal())
	artifact := preparedTestArtifact(t, plan, []byte(`{}`))
	at := lease.ExpiresAt().Add(-time.Millisecond)
	for _, value := range [][]byte{nil, []byte(`{}`), append(append([]byte(nil), artifact...), byte(' '))} {
		if _, err := coordinator.PrepareContextAbstention(ctx, plan, lease, value, RunFailurePolicy, at); err == nil {
			t.Fatal("malformed artifact accepted")
		}
	}
	if _, err := coordinator.PrepareContextAbstention(ctx, plan, lease, artifact, RunFailureTransient, at); err == nil {
		t.Fatal("foreign failure accepted")
	}
	prepared, err := coordinator.PrepareContextAbstention(ctx, plan, lease, artifact, RunFailurePolicy, at)
	if err != nil {
		t.Fatal(err)
	}
	altered := prepared.event
	altered.preparedArtifact = append([]byte(nil), altered.preparedArtifact...)
	altered.preparedArtifact[0] = 'X'
	if _, err := ReplayReviewRun(plan, []RunEvent{altered}); err == nil {
		t.Fatal("tampered event accepted")
	}
	other := prepared
	other.event.outputIdentity = strings.Repeat("a", 64)
	if _, err := coordinator.SettlePreparedContextAbstention(ctx, plan, other, lease.ExpiresAt().Add(time.Millisecond)); err == nil {
		t.Fatal("foreign descriptor accepted")
	}
}
func TestConcurrentPreparedSettlementExactlyOnce(t *testing.T) {
	ctx := context.Background()
	coordinator, plan, lease := preparedTestLease(t, NewMemoryRunJournal())
	artifact := preparedTestArtifact(t, plan, []byte(`{}`))
	prepared, err := coordinator.PrepareContextAbstention(ctx, plan, lease, artifact, RunFailurePolicy, lease.ExpiresAt().Add(-time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := coordinator.SettlePreparedContextAbstention(ctx, plan, prepared, lease.ExpiresAt().Add(time.Millisecond))
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
}

type preparedAppendFaultJournal struct {
	RunJournal
	fault error
	after bool
	fail  bool
}

func (j *preparedAppendFaultJournal) Append(ctx context.Context, head string, event RunEvent) error {
	if j.fail && (event.Kind() == RunEventContextAbstentionPrepared || event.Kind() == RunEventTaskFailed && event.OutputIdentity() != "") {
		j.fail = false
		if j.after {
			if err := j.RunJournal.Append(ctx, head, event); err != nil {
				return err
			}
		}
		return j.fault
	}
	return j.RunJournal.Append(ctx, head, event)
}
func TestPreparedIntentAppendErrorsFailClosed(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{true: "commit-then-error", false: "no-commit"}[after], func(t *testing.T) {
			ctx := context.Background()
			fault := errors.New("injected journal error")
			journal := &preparedAppendFaultJournal{RunJournal: NewMemoryRunJournal(), fault: fault, after: after}
			coordinator, plan, lease := preparedTestLease(t, journal)
			artifact := preparedTestArtifact(t, plan, []byte(`{}`))
			journal.fail = true
			_, err := coordinator.PrepareContextAbstention(ctx, plan, lease, artifact, RunFailurePolicy, lease.ExpiresAt().Add(-time.Millisecond))
			if !errors.Is(err, fault) {
				t.Fatalf("prepare error %v", err)
			}
			restarted, _ := NewCoordinator(journal)
			_, state, err := restarted.Resume(ctx, plan.Scope())
			if err != nil {
				t.Fatal(err)
			}
			runtime, _ := state.Task("context")
			prepared, ok := runtime.PreparedContextAbstention()
			if ok != after {
				t.Fatal("commit status mismatch")
			}
			if !ok {
				prepared, err = restarted.PrepareContextAbstention(ctx, plan, lease, artifact, RunFailurePolicy, lease.ExpiresAt().Add(-time.Millisecond))
				if err != nil {
					t.Fatal(err)
				}
			}
			journal.fail = true
			_, err = restarted.SettlePreparedContextAbstention(ctx, plan, prepared, lease.ExpiresAt().Add(time.Millisecond))
			if !errors.Is(err, fault) {
				t.Fatalf("settle error %v", err)
			}
			_, state, err = restarted.Resume(ctx, plan.Scope())
			if err != nil {
				t.Fatal(err)
			}
			runtime, _ = state.Task("context")
			if after && runtime.Status() != TaskRuntimeFailed || !after && runtime.Status() != TaskRuntimeLeased {
				t.Fatal("settlement append status")
			}
			state, err = restarted.SettlePreparedContextAbstention(ctx, plan, prepared, lease.ExpiresAt().Add(2*time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			runtime, _ = state.Task("context")
			if runtime.Status() != TaskRuntimeFailed || runtime.OutputIdentity() != prepared.ArtifactIdentity() {
				t.Fatal("retry lost artifact")
			}
		})
	}
}
func TestPreparedEventFileJournalLargeRecordRestart(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, plan, lease := preparedTestLease(t, journal)
	artifact := preparedTestArtifact(t, plan, bytes.Repeat([]byte("x"), 128<<10))
	prepared, err := coordinator.PrepareContextAbstention(ctx, plan, lease, artifact, RunFailurePolicy, lease.ExpiresAt().Add(-time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	event, err := EncodeRunEvent(prepared.event)
	if err != nil || len(event) <= maxEncodedRunEventBytes {
		t.Fatalf("not a large v3 event %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	recoverer, _ := NewCoordinator(restarted)
	_, state, err := recoverer.Resume(ctx, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := state.Task("context")
	restored, ok := runtime.PreparedContextAbstention()
	if !ok || restored.Identity() != prepared.Identity() || !bytes.Equal(restored.EncodedArtifact(), artifact) {
		t.Fatal("v3 file restart did not preserve descriptor")
	}
}

func TestPreparedV3ReplayRejectsMalformedSequenceAndMismatchedSettlement(t *testing.T) {
	ctx := context.Background()
	journal := NewMemoryRunJournal()
	coordinator, plan, lease := preparedTestLease(t, journal)
	artifact := preparedTestArtifact(t, plan, []byte(`{}`))
	prepared, err := coordinator.PrepareContextAbstention(ctx, plan, lease, artifact, RunFailurePolicy, lease.ExpiresAt().Add(-time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	events, err := readAllRunEvents(ctx, journal, plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	absent := append([]RunEvent(nil), events[:len(events)-1]...)
	settlement, err := NewRunEvent(plan, uint64(len(events)+1), prepared.Identity(), RunEventTaskFailed, func() TaskDefinition { task, _ := plan.Task("context"); return task }(), lease.Attempt(), prepared.LeaseTokenIdentity(), "", time.Time{}, prepared.ArtifactIdentity(), RunFailurePolicy, time.Time{}, lease.ExpiresAt().Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	absent = append(absent, settlement)
	if _, err := ReplayReviewRun(plan, absent); err == nil {
		t.Fatal("missing prepared predecessor accepted")
	}
	corrupted := append([]RunEvent(nil), events...)
	foreign := events[len(events)-1]
	foreign.outputIdentity = strings.Repeat("f", 64)
	foreign.identity = deriveRunEventIdentity(foreign)
	corrupted[len(corrupted)-1] = foreign
	if _, err := ReplayReviewRun(plan, corrupted); err == nil {
		t.Fatal("mismatched artifact accepted")
	}
	wrong, err := NewRunEvent(plan, uint64(len(events)+1), prepared.Identity(), RunEventTaskFailed, func() TaskDefinition { task, _ := plan.Task("context"); return task }(), lease.Attempt(), prepared.LeaseTokenIdentity(), "", time.Time{}, "", RunFailureResourceLimit, time.Time{}, lease.ExpiresAt().Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReplayReviewRun(plan, append(events, wrong)); err == nil {
		t.Fatal("empty generic expiry settled prepared intent")
	}
	encoded, err := EncodeRunEvent(prepared.event)
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(encoded, []byte(`"schema_version":3`), []byte(`"schema_version":2`), 1)
	if _, err := ParseRunEvent(bad); err == nil {
		t.Fatal("v2 accepted prepared event")
	}
	if _, err := ParseRunEvent(append(encoded, bytes.Repeat([]byte(" "), maxEncodedRunEventV3Bytes)...)); err == nil {
		t.Fatal("oversized v3 accepted")
	}
	old, _ := EncodeRunEvent(events[0])
	if _, err := ParseRunEvent(old); err != nil {
		t.Fatalf("v1 readback %v", err)
	}
}

func TestPreparedEventEightMiBArtifactBoundary(t *testing.T) {
	plan := runPlanFixture(t)
	max := preparedTestArtifact(t, plan, bytes.Repeat([]byte("x"), maxPreparedPayloadBytes))
	identity, err := preparedArtifactIdentity(max, plan.Scope())
	if err != nil || identity == "" {
		t.Fatalf("8 MiB artifact rejected: %v", err)
	}
	task, _ := plan.Task("context")
	event := RunEvent{scope: plan.Scope(), planIdentity: plan.Identity(), sequence: 2, previousIdentity: strings.Repeat("a", 64), kind: RunEventContextAbstentionPrepared, taskKey: task.Key(), taskIdentity: task.Identity(), attempt: 1, leaseTokenIdentity: strings.Repeat("b", 64), outputIdentity: identity, failure: RunFailurePolicy, occurredAtMillis: 200, preparedArtifact: max}
	event.identity = deriveRunEventIdentity(event)
	encoded, err := EncodeRunEvent(event)
	if err != nil || len(encoded) > maxEncodedRunEventV3Bytes || len(encoded) < maxEncodedRunEventV3Bytes/2 {
		t.Fatalf("bounded v3 encoding length=%d err=%v", len(encoded), err)
	}
	parsed, err := ParseRunEvent(encoded)
	if err != nil || parsed.Identity() != event.Identity() {
		t.Fatalf("large v3 parse %v", err)
	}
	over := preparedTestArtifact(t, plan, bytes.Repeat([]byte("x"), maxPreparedPayloadBytes+1))
	if _, err := preparedArtifactIdentity(over, plan.Scope()); err == nil {
		t.Fatal("artifact payload over 8 MiB accepted")
	}
}
