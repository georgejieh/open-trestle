package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
)

func TestPacketOwnerIntentPinsExactCandidateBeforePut(t *testing.T) {
	f := newLocalPacketOwnerFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseGate := func() { once.Do(func() { close(release) }) }
	defer releaseGate()
	f.owner.beforeRawPut = func() { close(entered); <-release }
	done := make(chan error, 1)
	go func() { _, err := f.owner.PreparePacket(context.Background(), f.request); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("owner did not reach Put")
	}
	head, present, err := f.journal.Head(context.Background(), f.request.Plan().Scope())
	if err != nil || !present {
		t.Fatalf("packet head: %t %v", present, err)
	}
	scope := f.request.Plan().Scope()
	record, err := os.ReadFile(filepath.Join(f.statePath, scope.Identity()+".scope-intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	var intent struct {
		Expected string `json:"expected"`
	}
	if err := json.Unmarshal(record, &intent); err != nil {
		t.Fatal(err)
	}
	if intent.Expected != head.PacketDescriptor().ArtifactIdentity || intent.Expected == f.request.Lease().Identity() {
		t.Fatalf("intent expected %s, candidate %s", intent.Expected, head.PacketDescriptor().ArtifactIdentity)
	}
	releaseGate()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPacketOwnerSourcePreflightDoesNotQuarantine(t *testing.T) {
	f := newLocalPacketOwnerFixture(t)
	f.owner.sourceRootDigest = strings.Repeat("f", 64)
	if _, err := f.owner.PreparePacket(context.Background(), f.request); err == nil {
		t.Fatal("source mismatch accepted")
	}
	marker := filepath.Join(f.statePath, f.request.Plan().Scope().Identity()+".scope-intent.json")
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source rejection left scope quarantined: %v", err)
	}
}

func TestPacketOwnerAfterPreparedCancellationRetainsCandidateQuarantineOnReopen(t *testing.T) {
	f := newLocalPacketOwnerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.owner.beforeRawPut = cancel
	if _, err := f.owner.PreparePacket(ctx, f.request); !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("prepared cancellation: %v", err)
	}
	head, present, err := f.journal.Head(context.Background(), f.request.Plan().Scope())
	if err != nil || !present {
		t.Fatalf("prepared head: %t %v", present, err)
	}
	if err := f.journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := controlplane.NewFileRunJournal(f.statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.InspectStartupInventory(context.Background()); !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("reopen inventory: %v", err)
	}
	if err := reopened.ReconcileScopeIntent(context.Background(), f.request.Plan().Scope(), "packet-prepare", f.request.Lease().Identity(), func(context.Context) error {
		t.Fatal("wrong candidate verifier ran")
		return nil
	}); !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		t.Fatalf("wrong candidate reconciled: %v", err)
	}
	record, err := os.ReadFile(filepath.Join(f.statePath, f.request.Plan().Scope().Identity()+".scope-intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	var intent struct {
		Expected string `json:"expected"`
	}
	if err := json.Unmarshal(record, &intent); err != nil || intent.Expected != head.PacketDescriptor().ArtifactIdentity {
		t.Fatalf("candidate quarantine: %v %s", err, intent.Expected)
	}
}
