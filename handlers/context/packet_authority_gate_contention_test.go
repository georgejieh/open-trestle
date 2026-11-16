package context

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
)

// A real gate witness distinguishes an Append call from a blocked Append.
func TestPacketAuthorityCanceledAppendContendsWithPhysicalPacketPut(t *testing.T) {
	authority, request, coordinator, store, root, closeFixture, wrapped := newPacketWriterFixture(t, false, false, false, false, false)
	defer closeFixture()
	journal := wrapped.RunJournal.(*controlplane.FileRunJournal)
	contention, unsubscribe, err := journal.WatchEffectGateContention()
	if err != nil {
		t.Fatal(err)
	}
	defer unsubscribe()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	barrier := &packetPutBarrier{Store: store, entered: make(chan artifact.Artifact), release: release, forwarded: make(chan error, 1)}
	authority.store = barrier
	preparedDone := make(chan error, 1)
	canceledDone := make(chan error, 1)
	prepareJoined, cancelStarted, cancelJoined := false, false, false
	defer func() {
		unblock()
		cleanup, stopCleanup := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCleanup()
		if !prepareJoined {
			select {
			case <-preparedDone:
			case <-cleanup.Done():
				t.Error("Prepare goroutine did not exit after barrier release")
			}
		}
		if cancelStarted && !cancelJoined {
			select {
			case <-canceledDone:
			case <-cleanup.Done():
				t.Error("CancelRun goroutine did not exit after barrier release")
			}
		}
	}()
	go func() { _, err := authority.Prepare(ctx, request); preparedDone <- err }()

	var exact artifact.Artifact
	select {
	case exact = <-barrier.entered:
	case <-ctx.Done():
		t.Fatal("physical packet Put did not enter barrier")
	}
	scope := request.Plan().Scope()
	_, before, err := coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	runtime, exists := before.Task("context")
	checkpoint, prepared := runtime.PreparedContextPacket()
	if !exists || !prepared || before.HeadIdentity() != checkpoint.Identity() || checkpoint.Descriptor().ArtifactIdentity != exact.Identity() {
		t.Fatal("durable v4 head does not identify blocked physical packet")
	}
	if _, err := store.Get(ctx, scope, exact.Identity(), time.UnixMilli(230)); !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("packet exists before forwarding Put: %v", err)
	}

	appending := make(chan struct{}, 1)
	wrapped.onCancelAppend = func() { appending <- struct{}{} }
	cancelStarted = true
	go func() { _, err := coordinator.CancelRun(ctx, request.Plan(), time.UnixMilli(231)); canceledDone <- err }()
	select {
	case <-appending:
	case <-ctx.Done():
		t.Fatal("CancelRun did not enter canceled Append")
	}
	// Current code completes cancellation instead of reporting contention.
	// Observe either outcome while the physical Put remains blocked.
	observation, stop := context.WithTimeout(ctx, 500*time.Millisecond)
	defer stop()
	gateContended, canceledEarly := false, false
	select {
	case <-contention:
		gateContended = true
	case err := <-canceledDone:
		cancelJoined = true
		if err != nil {
			t.Fatalf("canceled Append failed before packet Put release: %v", err)
		}
		canceledEarly = true
	case <-observation.Done():
		if ctx.Err() != nil {
			t.Fatal("test deadline before gate observation")
		}
	}
	_, held, err := coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	canceledHeadWhileHeld := held.Status() == controlplane.ReviewRunCanceled
	heldReceipt, err := coordinator.Receipt(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	canceledReceiptWhileHeld := heldReceipt.Status() == controlplane.ReviewRunCanceled
	if gateContended {
		select {
		case err := <-canceledDone:
			cancelJoined = true
			t.Errorf("cancellation returned while physical Put blocked: %v", err)
			canceledEarly = true
		default:
		}
	}
	if _, err := store.Get(ctx, scope, exact.Identity(), time.UnixMilli(230)); !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("packet exists while physical Put is blocked: %v", err)
	}
	select {
	case err := <-preparedDone:
		prepareJoined = true
		t.Fatalf("Prepare returned before physical Put release: %v", err)
	default:
	}
	unblock()
	select {
	case err := <-barrier.forwarded:
		if err != nil {
			t.Fatalf("real FileStore Put failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("forwarded physical Put did not finish")
	}
	select {
	case err := <-preparedDone:
		prepareJoined = true
		if err != nil && !errors.Is(err, ErrPacketAuthority) {
			t.Fatalf("unexpected Prepare error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Prepare did not finish")
	}
	if !canceledEarly {
		select {
		case err := <-canceledDone:
			cancelJoined = true
			if err != nil {
				t.Fatalf("CancelRun after Put: %v", err)
			}
		case <-ctx.Done():
			t.Fatal("CancelRun did not finish after Put")
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
	if err != nil || durable.Status() != controlplane.ReviewRunCanceled {
		t.Fatalf("reopened canceled state: %v, %v", durable.Status(), err)
	}
	receipt, err := recovered.Receipt(ctx, scope)
	if err != nil || receipt.Status() != controlplane.ReviewRunCanceled || receipt.OutputIdentity() != "" || receipt.HeadIdentity() != durable.HeadIdentity() {
		t.Fatalf("reopened no-output canceled receipt: %v", err)
	}
	persisted, err := reopenedStore.Get(ctx, scope, exact.Identity(), time.UnixMilli(232))
	if err != nil || !samePacketArtifact(exact, persisted) {
		t.Fatalf("reopened exact packet differs: %v", err)
	}
	expectedBytes, err := artifact.Encode(exact)
	if err != nil {
		t.Fatal(err)
	}
	reopenedBytes, err := artifact.Encode(persisted)
	if err != nil || !bytes.Equal(expectedBytes, reopenedBytes) {
		t.Fatalf("reopened packet envelope bytes differ: %v", err)
	}
	events, err := reopenedJournal.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) < 2 || events[len(events)-2].Identity() != checkpoint.Identity() || events[len(events)-1].Kind() != controlplane.RunEventCanceled {
		t.Fatal("reopened v4 / canceled event order differs")
	}
	if !gateContended || canceledEarly || canceledHeadWhileHeld || canceledReceiptWhileHeld {
		t.Errorf("no shared gate ordering during physical Put: contention=%t earlyCancel=%t canceledHeadWhileHeld=%t canceledReceiptWhileHeld=%t", gateContended, canceledEarly, canceledHeadWhileHeld, canceledReceiptWhileHeld)
	}
}

func TestPacketAuthorityCancelFirstNeverForwardsPacketPut(t *testing.T) {
	authority, request, coordinator, store, root, closeFixture, _ := newPacketWriterFixture(t, false, false, false, false, false)
	defer closeFixture()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	scope := request.Plan().Scope()
	canceled, err := coordinator.CancelRun(ctx, request.Plan(), time.UnixMilli(231))
	if err != nil || canceled.Status() != controlplane.ReviewRunCanceled {
		t.Fatalf("real cancellation failed: %v", err)
	}
	puts := 0
	authority.store = blockedPacketStore{Store: store, putCount: &puts}
	if _, err := authority.Prepare(ctx, request); !errors.Is(err, ErrPacketAuthority) {
		t.Fatalf("Prepare after durable cancellation: %v", err)
	}
	if puts != 0 {
		t.Fatalf("physical Put forwarded after durable cancellation: %d", puts)
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
	if err != nil || durable.Status() != controlplane.ReviewRunCanceled {
		t.Fatalf("reopened canceled state: %v, %v", durable.Status(), err)
	}
	receipt, err := recovered.Receipt(ctx, scope)
	if err != nil || receipt.OutputIdentity() != "" || receipt.Status() != controlplane.ReviewRunCanceled {
		t.Fatalf("reopened no-output receipt: %v", err)
	}
	events, err := reopenedJournal.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Kind() == controlplane.RunEventContextPacketPrepared {
			t.Fatal("v4 persisted after cancel-first")
		}
	}
	// Inspect reopened physical files: no descriptor exists to name a packet.
	entries, err := os.ReadDir(filepath.Join(root, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, "artifacts", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		value, err := artifact.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		if value.Kind() == artifact.KindContextPacket {
			t.Fatal("physical packet persisted after cancel-first")
		}
	}
}
