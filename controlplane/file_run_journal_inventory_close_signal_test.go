package controlplane

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A Close announcement must reject inventory while an actual effect owns the
// gate token, before Close can acquire the token and retire j.closed.
func TestStartupInventoryRejectsAnnouncedCloseWhileEffectHeld(t *testing.T) {
	j, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseEffect := func() { releaseOnce.Do(func() { close(release) }) }
	effectDone := make(chan error, 1)
	go func() {
		effectDone <- j.WithEffectSection(context.Background(), func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	closeDone := make(chan error, 1)
	closeStarted := false
	defer func() {
		releaseEffect()
		select {
		case err := <-effectDone:
			if err != nil {
				t.Errorf("effect cleanup: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("effect cleanup did not finish")
		}
		if !closeStarted {
			go func() { closeDone <- j.Close() }()
		}
		select {
		case err := <-closeDone:
			if err != nil {
				t.Errorf("Close cleanup: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Close cleanup did not finish")
		}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("effect did not acquire gate")
	}
	closeStarted = true
	go func() { closeDone <- j.Close() }()
	select {
	case <-j.closingSignal:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not announce closing")
	}
	// Inspectors use a bounded join: a regression must not strand the test.
	inventoryDone := make(chan error, 1)
	go func() {
		inventory, err := j.InspectStartupInventory(context.Background())
		if inventory != (StartupInventory{}) || !errors.Is(err, ErrRunJournalClosed) {
			inventoryDone <- fmt.Errorf("inventory=%+v err=%v, want zero and ErrRunJournalClosed", inventory, err)
			return
		}
		inventoryDone <- nil
	}()
	factsDone := make(chan error, 1)
	go func() {
		facts, err := j.InspectHistoricalContextPackets(context.Background())
		if facts != nil || !errors.Is(err, ErrRunJournalClosed) {
			factsDone <- fmt.Errorf("facts=%v err=%v, want nil and ErrRunJournalClosed", facts, err)
			return
		}
		factsDone <- nil
	}()
	for name, done := range map[string]<-chan error{"inventory": inventoryDone, "facts": factsDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%s blocked during announced Close", name)
		}
	}
	select {
	case err := <-closeDone:
		t.Errorf("Close finished before effect released: %v", err)
	default:
	}
}

// Repeated concurrent subscription, inspection and Close cannot create the
// former gateMu -> mu -> gateMu cycle. Every worker has a bounded join.
func TestStartupInventoryWatchContentionAndCloseConcurrent(t *testing.T) {
	for round := 0; round < 8; round++ {
		j, err := NewFileRunJournal(filepath.Join(t.TempDir(), "journal"))
		if err != nil {
			t.Fatal(err)
		}
		entered, release := make(chan struct{}), make(chan struct{})
		effectDone := make(chan error, 1)
		go func() {
			effectDone <- j.WithEffectSection(context.Background(), func() error {
				close(entered)
				<-release
				return nil
			})
		}()
		select {
		case <-entered:
		case <-time.After(2 * time.Second):
			close(release)
			t.Fatal("effect did not acquire gate")
		}
		const workers = 12
		start := make(chan struct{})
		results := make(chan error, 2*workers)
		for i := 0; i < workers; i++ {
			go func() {
				<-start
				_, unsubscribe, err := j.WatchEffectGateContention()
				if err == nil {
					unsubscribe()
				}
				if err != nil && !errors.Is(err, ErrRunJournalClosed) && !errors.Is(err, ErrInvalidRunJournalEffectSection) {
					results <- fmt.Errorf("watch: %w", err)
					return
				}
				results <- nil
			}()
			go func() {
				<-start
				inventory, err := j.InspectStartupInventory(context.Background())
				if inventory != (StartupInventory{}) || (err != nil && !errors.Is(err, ErrRunJournalClosed)) {
					results <- fmt.Errorf("inspect: inventory=%+v err=%v", inventory, err)
					return
				}
				results <- nil
			}()
		}
		closeDone := make(chan error, 1)
		close(start)
		go func() { closeDone <- j.Close() }()
		for i := 0; i < 2*workers; i++ {
			select {
			case err := <-results:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(2 * time.Second):
				t.Error("watch or inspect blocked")
				// Do not block cleanup if a lock-order regression has deadlocked.
				i = 2 * workers
			}
		}
		close(release)
		select {
		case err := <-effectDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("effect did not finish")
		}
		select {
		case err := <-closeDone:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Close did not finish")
		}
	}
}
