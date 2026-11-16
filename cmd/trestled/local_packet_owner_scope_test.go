package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
)

func TestPacketOwnerScopeGateBlocksOrdinaryJournalWrite(t *testing.T) {
	f := newLocalPacketOwnerFixture(t)
	prepared := make(chan error, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	f.owner.beforeRawPut = func() { close(entered); <-release }
	go func() { _, err := f.owner.PreparePacket(context.Background(), f.request); prepared <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("owner never entered Put")
	}
	err := f.journal.SavePlan(context.Background(), f.request.Plan())
	if !errors.Is(err, controlplane.ErrScopeIntentUnresolved) {
		close(release)
		t.Fatalf("ordinary journal write inside owner Put: %v", err)
	}
	close(release)
	if err := <-prepared; err != nil {
		t.Fatal(err)
	}
}
