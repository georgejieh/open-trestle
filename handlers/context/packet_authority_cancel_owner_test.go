package context

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
)

// packetPutBarrier stops only the physical packet Put, before forwarding to the
// real FileStore. All other artifact operations use the real store unchanged.
type packetPutBarrier struct {
	artifact.Store
	entered   chan artifact.Artifact
	release   <-chan struct{}
	forwarded chan error
}

func (s *packetPutBarrier) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	if value.Kind() != artifact.KindContextPacket {
		return s.Store.Put(ctx, value, at)
	}
	s.entered <- value
	<-s.release
	created, err := s.Store.Put(ctx, value, at)
	s.forwarded <- err
	return created, err
}

func TestPacketAuthorityCancellationCannotCommitDuringPhysicalPut(t *testing.T) {
	authority, request, coordinator, store, root, closeFixture, wrappedJournal := newPacketWriterFixture(t, false, false, false, false, false)
	defer closeFixture()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	barrier := &packetPutBarrier{
		Store: store, entered: make(chan artifact.Artifact), release: release,
		forwarded: make(chan error, 1),
	}
	authority.store = barrier
	prepareDone := make(chan error, 1)
	go func() { _, err := authority.Prepare(ctx, request); prepareDone <- err }()

	var exact artifact.Artifact
	select {
	case exact = <-barrier.entered:
	case <-ctx.Done():
		t.Fatal("packet Put never reached physical-store barrier")
	}
	scope := request.Plan().Scope()
	_, before, err := coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	runtime, exists := before.Task("context")
	checkpoint, prepared := runtime.PreparedContextPacket()
	if !exists || !prepared || checkpoint.Descriptor().ArtifactIdentity != exact.Identity() || before.HeadIdentity() != checkpoint.Identity() {
		t.Fatal("v4 prepared checkpoint was not durably visible before packet Put")
	}
	if _, err := store.Get(ctx, scope, exact.Identity(), time.UnixMilli(230)); !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("packet bytes existed before forwarded Put: %v", err)
	}

	// This callback is invoked by the fixture-owned journal wrapper at the
	// actual canceled Append boundary, not when the cancel goroutine starts.
	appending := make(chan struct{}, 1)
	wrappedJournal.onCancelAppend = func() { appending <- struct{}{} }
	canceledDone := make(chan error, 1)
	go func() {
		_, err := coordinator.CancelRun(ctx, request.Plan(), time.UnixMilli(231))
		canceledDone <- err
	}()
	select {
	case <-appending:
	case <-ctx.Done():
		t.Fatal("CancelRun did not reach canceled journal Append")
	}

	// A bounded liveness check, not a delay to choose an interleaving: the
	// packet remains blocked until after this check on both implementations.
	observation, stopObservation := context.WithTimeout(ctx, 2*time.Second)
	defer stopObservation()
	committedWhileHeld := false
	select {
	case err := <-canceledDone:
		if err != nil {
			t.Fatalf("canceled Append returned without durable success: %v", err)
		}
		committedWhileHeld = true
	case <-observation.Done():
		if ctx.Err() != nil {
			t.Fatal("test deadline before cancellation observation")
		}
	}
	events, err := wrappedJournal.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || events[len(events)-1].Kind() == controlplane.RunEventCanceled {
		committedWhileHeld = true
	}
	select {
	case err := <-prepareDone:
		t.Fatalf("Prepare returned before physical Put was released: %v", err)
	default:
	}
	unblock()
	select {
	case err := <-barrier.forwarded:
		if err != nil {
			t.Fatalf("real FileStore packet Put failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("physical packet Put did not finish")
	}
	select {
	case err := <-prepareDone:
		if err != nil && !errors.Is(err, ErrPacketAuthority) {
			t.Fatalf("unexpected Prepare error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Prepare did not finish")
	}
	if !committedWhileHeld {
		select {
		case err := <-canceledDone:
			if err != nil {
				t.Fatalf("CancelRun after packet Put: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("CancelRun did not finish after packet Put")
		}
	}
	closeFixture()
	reopenedJournal, err := controlplane.NewFileRunJournal(filepath.Join(root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedJournal.Close()
	reopenedStore, err := artifact.NewFileStore(filepath.Join(root, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedStore.Close()
	recovered, _ := controlplane.NewCoordinator(reopenedJournal)
	_, durable, err := recovered.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if durable.Status() != controlplane.ReviewRunCanceled {
		t.Fatalf("reopened run status=%v, want canceled", durable.Status())
	}
	receipt, err := recovered.Receipt(ctx, scope)
	if err != nil || receipt.Status() != controlplane.ReviewRunCanceled || receipt.HeadIdentity() != durable.HeadIdentity() || receipt.OutputIdentity() != "" {
		t.Fatalf("reopened canceled receipt differs from no-output journal: %v", err)
	}
	persisted, err := reopenedStore.Get(ctx, scope, exact.Identity(), time.UnixMilli(232))
	if err != nil || !samePacketArtifact(exact, persisted) {
		t.Fatalf("reopened packet differs from exact forwarded artifact: %v", err)
	}
	durableEvents, err := reopenedJournal.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(durableEvents) < 2 || durableEvents[len(durableEvents)-2].Identity() != checkpoint.Identity() || durableEvents[len(durableEvents)-1].Kind() != controlplane.RunEventCanceled {
		t.Fatal("durable v4 preparation/cancellation order changed")
	}
	if committedWhileHeld {
		t.Error("terminal canceled append durably committed while physical packet Put was blocked; packet bytes forwarded afterward")
	}
}

var _ artifact.Store = (*packetPutBarrier)(nil)
