package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
)

func TestLocalPacketOwnerLoadsOnlyLivePreparedPacket(t *testing.T) {
	ctx := context.Background()
	fixture := newLocalPacketOwnerFixture(t)
	prepared, err := fixture.owner.PreparePacket(ctx, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := fixture.owner.LoadPreparedPacket(ctx, fixture.request, prepared)
	if err != nil || loaded.Identity() != prepared.Descriptor().ArtifactIdentity || loaded.Kind() != artifact.KindContextPacket {
		t.Fatalf("live packet read: %v", err)
	}
	candidate, candidateErr := fixture.owner.LoadPreparedPacketCandidate(ctx, fixture.request, prepared)
	if candidateErr != nil || candidate.Artifact().Identity() != loaded.Identity() || candidate.Packet().Identity() == "" || candidate.Snapshot().Identity() != prepared.Descriptor().SnapshotIdentity {
		t.Fatalf("live typed packet read: %v", candidateErr)
	}
	stored, err := fixture.store.Get(ctx, fixture.request.Plan().Scope(), loaded.Identity(), fixture.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	want, wantErr := artifact.Encode(stored)
	got, gotErr := artifact.Encode(loaded)
	if wantErr != nil || gotErr != nil || !bytes.Equal(want, got) {
		t.Fatal("loaded packet differs from stored envelope")
	}
	if _, err := fixture.owner.LoadPreparedPacket(ctx, fixture.request, controlplane.PreparedContextPacket{}); !errors.Is(err, contexthandler.ErrPacketAuthority) {
		t.Fatalf("unprepared packet read: %v", err)
	}
	if candidate, err := fixture.owner.LoadPreparedPacketCandidate(ctx, fixture.request, controlplane.PreparedContextPacket{}); !errors.Is(err, contexthandler.ErrPacketAuthority) || candidate.Packet().Identity() != "" {
		t.Fatalf("unprepared typed packet read: %v", err)
	}
	changedRoot := *fixture.owner
	changedRoot.sourceRootDigest = strings.Repeat("a", 64)
	if _, err := changedRoot.LoadPreparedPacket(ctx, fixture.request, prepared); !errors.Is(err, contexthandler.ErrPacketAuthority) {
		t.Fatalf("changed source root read: %v", err)
	}
	if candidate, err := changedRoot.LoadPreparedPacketCandidate(ctx, fixture.request, prepared); !errors.Is(err, contexthandler.ErrPacketAuthority) || candidate.Packet().Identity() != "" {
		t.Fatalf("changed root typed packet read: %v", err)
	}
	expired := *fixture.owner
	expired.clock = localPacketFixtureClock{at: fixture.request.Lease().ExpiresAt()}
	if candidate, err := expired.LoadPreparedPacketCandidate(ctx, fixture.request, prepared); !errors.Is(err, contexthandler.ErrPacketAuthority) || candidate.Packet().Identity() != "" {
		t.Fatalf("expired lease typed packet read: %v", err)
	}
	if _, err := fixture.coordinator.CancelRun(ctx, fixture.request.Plan(), time.UnixMilli(240)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.owner.LoadPreparedPacket(ctx, fixture.request, prepared); !errors.Is(err, contexthandler.ErrPacketAuthority) {
		t.Fatalf("terminal packet read: %v", err)
	}
	if candidate, err := fixture.owner.LoadPreparedPacketCandidate(ctx, fixture.request, prepared); !errors.Is(err, contexthandler.ErrPacketAuthority) || candidate.Packet().Identity() != "" {
		t.Fatalf("terminal typed packet read: %v", err)
	}
}

// This suite intentionally uses only the Git-qualified boot-returned owner and
// the raw boot journal/store. No constructed packet authority is privileged.
const ownerGatePhaseLimit = 5 * time.Second

type ownerGateResult struct {
	prepared controlplane.PreparedContextPacket
	err      error
}

type ownerGateCancellation struct {
	state controlplane.ReviewRunState
	err   error
}

type ownerGateExpected struct {
	value      artifact.Artifact
	descriptor controlplane.ContextPacketDescriptor
	history    []controlplane.RunEvent
}

func ownerGateAwait[T any](t *testing.T, label string, result <-chan T) T {
	t.Helper()
	deadline := time.NewTimer(ownerGatePhaseLimit)
	defer deadline.Stop()
	select {
	case got := <-result:
		return got
	case <-deadline.C:
		t.Fatalf("timed out waiting for %s", label)
		var zero T
		return zero
	}
}

func ownerGateFinished(t *testing.T, label string, done <-chan struct{}) {
	t.Helper()
	deadline := time.NewTimer(ownerGatePhaseLimit)
	defer deadline.Stop()
	select {
	case <-done:
	case <-deadline.C:
		t.Errorf("%s goroutine did not stop after barrier release", label)
	}
}

func ownerGateCandidate(t *testing.T, fixture localPacketOwnerFixture) ownerGateExpected {
	t.Helper()
	ctx, scope, at := context.Background(), fixture.request.Plan().Scope(), fixture.clock.Now()
	_, state, err := fixture.coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	history, err := fixture.journal.Read(ctx, scope, 0, 100)
	if err != nil || len(history) == 0 {
		t.Fatalf("read baseline journal: %v", err)
	}
	if history[len(history)-1].Identity() != state.HeadIdentity() {
		t.Fatal("baseline head differs from journal")
	}
	candidate, err := contexthandler.BuildPacketCandidate(ctx, localPacketFixtureReader{fixture.store}, fixture.request, state, fixture.clock, fixture.rootDigest, at, at)
	if err != nil {
		t.Fatal(err)
	}
	value, descriptor := candidate.Artifact(), candidate.Descriptor()
	assertLocalPacketOracle(t, fixture, state, value, descriptor)
	ownerGateAbsent(t, fixture.store, fixture, value)
	return ownerGateExpected{value: value, descriptor: descriptor, history: history}
}

func ownerGateAbsent(t *testing.T, store *artifact.FileStore, fixture localPacketOwnerFixture, value artifact.Artifact) {
	t.Helper()
	_, err := store.Get(context.Background(), fixture.request.Plan().Scope(), value.Identity(), fixture.clock.Now())
	if !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("packet bytes unexpectedly available: %v", err)
	}
}

func ownerGateHistory(t *testing.T, journal *controlplane.FileRunJournal, fixture localPacketOwnerFixture, expected ownerGateExpected, kinds ...controlplane.RunEventKind) []controlplane.RunEvent {
	t.Helper()
	events, err := journal.Read(context.Background(), fixture.request.Plan().Scope(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(expected.history)+len(kinds) {
		t.Fatalf("journal length = %d, baseline = %d, expected additions = %v", len(events), len(expected.history), kinds)
	}
	for i, prior := range expected.history {
		if events[i].Identity() != prior.Identity() || events[i].Sequence() != prior.Sequence() || events[i].PreviousIdentity() != prior.PreviousIdentity() || events[i].Kind() != prior.Kind() {
			t.Fatalf("baseline event %d changed", i)
		}
	}
	previous := expected.history[len(expected.history)-1]
	for i, kind := range kinds {
		event := events[len(expected.history)+i]
		if event.Kind() != kind || event.Sequence() != previous.Sequence()+1 || event.PreviousIdentity() != previous.Identity() || event.PlanIdentity() != fixture.request.Plan().Identity() || event.Scope().Identity() != fixture.request.Plan().Scope().Identity() {
			t.Fatalf("incorrect %s event chain at offset %d", kind, i)
		}
		if kind == controlplane.RunEventContextPacketPrepared {
			if event.TaskKey() != fixture.request.Task().Key() || event.TaskIdentity() != fixture.request.Task().Identity() || event.Attempt() != fixture.request.Lease().Attempt() || event.OutputIdentity() != expected.value.Identity() || !reflect.DeepEqual(event.PacketDescriptor(), expected.descriptor) || len(event.PreparedArtifact()) != 0 {
				t.Fatalf("v4 is not exact content-free candidate intent: %s", event.Identity())
			}
		} else if kind == controlplane.RunEventCanceled {
			if event.Failure() != controlplane.RunFailureCanceled || event.OutputIdentity() != "" || event.TaskKey() != "" || !event.OccurredAt().Equal(time.UnixMilli(240)) {
				t.Fatalf("canceled event is not the exact terminal transition: %s", event.Identity())
			}
		}
		previous = event
	}
	head, present, err := journal.Head(context.Background(), fixture.request.Plan().Scope())
	if err != nil || !present || head.Identity() != previous.Identity() {
		t.Fatalf("journal head disagrees with history: %v", err)
	}
	return events
}

func ownerGateReopen(t *testing.T, fixture localPacketOwnerFixture) (*controlplane.FileRunJournal, *artifact.FileStore) {
	t.Helper()
	if err := fixture.resources.Close(); err != nil {
		t.Fatalf("close boot resources before reopen: %v", err)
	}
	journal, err := controlplane.NewFileRunJournal(fixture.statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Errorf("close reopened journal: %v", err)
		}
	})
	store, err := artifact.NewFileStore(filepath.Join(fixture.statePath, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close reopened store: %v", err)
		}
	})
	return journal, store
}

func TestLocalPacketOwnerGateV4FirstCancelWaitsForRawPut(t *testing.T) {
	fixture := newLocalPacketOwnerFixture(t)
	expected := ownerGateCandidate(t, fixture)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	fixture.owner.beforeRawPut = func() { close(entered); <-release }
	ownerResults := make(chan ownerGateResult, 1)
	ownerDone := make(chan struct{})
	go func() {
		defer close(ownerDone)
		prepared, err := fixture.owner.PreparePacket(context.Background(), fixture.request)
		ownerResults <- ownerGateResult{prepared, err}
	}()
	var cancelDone <-chan struct{}
	t.Cleanup(func() {
		unblock()
		ownerGateFinished(t, "owner", ownerDone)
		if cancelDone != nil {
			ownerGateFinished(t, "cancel", cancelDone)
		}
	})
	ownerGateAwait(t, "post-v4 pre-Put barrier", entered)
	preparedEvents := ownerGateHistory(t, fixture.journal, fixture, expected, controlplane.RunEventContextPacketPrepared)
	ownerGateAbsent(t, fixture.store, fixture, expected.value)

	watcher, unwatch, err := fixture.journal.WatchEffectGateContention()
	if err != nil {
		t.Fatal(err)
	}
	defer unwatch()
	other, err := controlplane.NewCoordinator(fixture.journal)
	if err != nil {
		t.Fatal(err)
	}
	cancelResults := make(chan ownerGateCancellation, 1)
	finished := make(chan struct{})
	cancelDone = finished
	go func() {
		defer close(finished)
		state, err := other.CancelRun(context.Background(), fixture.request.Plan(), time.UnixMilli(240))
		cancelResults <- ownerGateCancellation{state, err}
	}()
	ownerGateAwait(t, "real canceled-Append gate contention", watcher)
	ownerGateHistory(t, fixture.journal, fixture, expected, controlplane.RunEventContextPacketPrepared)
	ownerGateAbsent(t, fixture.store, fixture, expected.value)
	select {
	case got := <-cancelResults:
		t.Fatalf("CancelRun returned before effect gate released: %v", got.err)
	default:
	}

	unblock()
	owner := ownerGateAwait(t, "owner preparation", ownerResults)
	if owner.err != nil || owner.prepared.Identity() != preparedEvents[len(preparedEvents)-1].Identity() || !reflect.DeepEqual(owner.prepared.Descriptor(), expected.descriptor) {
		t.Fatalf("owner prepared wrong intent: %v", owner.err)
	}
	canceled := ownerGateAwait(t, "durable cancellation", cancelResults)
	if canceled.err != nil || canceled.state.Status() != controlplane.ReviewRunCanceled {
		t.Fatalf("cancel did not reach terminal state: %v", canceled.err)
	}
	ownerGateFinished(t, "owner", ownerDone)
	ownerGateFinished(t, "cancel", finished)
	journal, store := ownerGateReopen(t, fixture)
	events := ownerGateHistory(t, journal, fixture, expected, controlplane.RunEventContextPacketPrepared, controlplane.RunEventCanceled)
	if canceled.state.HeadIdentity() != events[len(events)-1].Identity() {
		t.Fatal("canceled state differs from durable canceled head")
	}
	stored, err := store.Get(context.Background(), fixture.request.Plan().Scope(), expected.value.Identity(), fixture.clock.Now())
	if err != nil {
		t.Fatalf("durable packet missing after v4-first Put: %v", err)
	}
	want, wantErr := artifact.Encode(expected.value)
	got, gotErr := artifact.Encode(stored)
	if wantErr != nil || gotErr != nil || !bytes.Equal(got, want) {
		t.Fatalf("reopened artifact envelope differs: want=%v got=%v", wantErr, gotErr)
	}
}

func TestLocalPacketOwnerGateCancelFirstDeclinesV4AndPut(t *testing.T) {
	fixture := newLocalPacketOwnerFixture(t)
	expected := ownerGateCandidate(t, fixture)
	other, err := controlplane.NewCoordinator(fixture.journal)
	if err != nil {
		t.Fatal(err)
	}
	canceled, err := other.CancelRun(context.Background(), fixture.request.Plan(), time.UnixMilli(240))
	if err != nil || canceled.Status() != controlplane.ReviewRunCanceled {
		t.Fatalf("cancel first: %v", err)
	}
	events := ownerGateHistory(t, fixture.journal, fixture, expected, controlplane.RunEventCanceled)
	if canceled.HeadIdentity() != events[len(events)-1].Identity() {
		t.Fatal("cancel head not durable")
	}
	if _, err := fixture.owner.PreparePacket(context.Background(), fixture.request); err == nil {
		t.Fatal("canceled run accepted owner preparation")
	}
	journal, store := ownerGateReopen(t, fixture)
	ownerGateHistory(t, journal, fixture, expected, controlplane.RunEventCanceled)
	ownerGateAbsent(t, store, fixture, expected.value)
}

func TestLocalPacketOwnerGateTimedOutWaiterCannotLatePut(t *testing.T) {
	fixture := newLocalPacketOwnerFixture(t)
	expected := ownerGateCandidate(t, fixture)
	unexpectedPut := make(chan struct{}, 1)
	fixture.owner.beforeRawPut = func() {
		select {
		case unexpectedPut <- struct{}{}:
		default:
		}
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	heldResults := make(chan error, 1)
	heldDone := make(chan struct{})
	go func() {
		defer close(heldDone)
		heldResults <- fixture.journal.WithEffectSection(context.Background(), func() error { close(entered); <-release; return nil })
	}()
	t.Cleanup(func() { unblock(); ownerGateFinished(t, "held section", heldDone) })
	ownerGateAwait(t, "test-held effect section", entered)
	watcher, unwatch, err := fixture.journal.WatchEffectGateContention()
	if err != nil {
		t.Fatal(err)
	}
	defer unwatch()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ownerResults := make(chan ownerGateResult, 1)
	ownerDone := make(chan struct{})
	go func() {
		defer close(ownerDone)
		prepared, err := fixture.owner.PreparePacket(ctx, fixture.request)
		ownerResults <- ownerGateResult{prepared, err}
	}()
	t.Cleanup(func() { unblock(); ownerGateFinished(t, "timed-out owner", ownerDone) })
	ownerGateAwait(t, "owner's real gate contention", watcher)
	ownerGateAwait(t, "owner context deadline", ctx.Done())
	result := ownerGateAwait(t, "owner gate-wait return", ownerResults)
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) || !errors.Is(result.err, controlplane.ErrRunJournalContextDone) {
		t.Fatalf("owner did not reject expired real-journal gate wait: %v", result.err)
	}
	ownerGateHistory(t, fixture.journal, fixture, expected)
	ownerGateAbsent(t, fixture.store, fixture, expected.value)
	unblock()
	if err := ownerGateAwait(t, "held section release", heldResults); err != nil {
		t.Fatalf("test-held section: %v", err)
	}
	ownerGateFinished(t, "timed-out owner", ownerDone)
	ownerGateFinished(t, "held section", heldDone)
	journal, store := ownerGateReopen(t, fixture)
	ownerGateHistory(t, journal, fixture, expected)
	ownerGateAbsent(t, store, fixture, expected.value)
	select {
	case <-unexpectedPut:
		t.Fatal("timed-out owner reached pre-Put hook")
	default:
	}
}
