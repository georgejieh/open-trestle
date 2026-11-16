package controlplane

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestRootedInventoryLifecycleAndInputs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rooted scanner is Linux-only")
	}
	root := filepath.Join(t.TempDir(), "journal")
	j, _ := rootedHistoricalPacketFixture(t, root, "lifecycle")
	if e := j.WithOwnedHistoricalPacketFacts(context.Background(), nil); !errors.Is(e, ErrInvalidRunJournalEffectSection) {
		t.Fatalf("nil use: %v", e)
	}
	var escaped HistoricalPacketScan
	e := j.WithOwnedHistoricalPacketFacts(context.Background(), func(_ *os.Root, scan HistoricalPacketScan) error {
		escaped = scan
		if e := scan(nil, func([]HistoricalContextPacketFact) error { return nil }); !errors.Is(e, ErrInvalidRunJournalContext) {
			t.Errorf("nil context: %v", e)
		}
		if e := scan(context.Background(), func([]HistoricalContextPacketFact) error { return nil }); !errors.Is(e, errHistoricalScannerUnavailable) {
			t.Errorf("second use: %v", e)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if e := escaped(context.Background(), nil); !errors.Is(e, errHistoricalScannerUnavailable) {
		t.Fatalf("escaped: %v", e)
	}
	e = j.WithOwnedHistoricalPacketFacts(context.Background(), func(_ *os.Root, scan HistoricalPacketScan) error {
		if e := scan(context.Background(), nil); !errors.Is(e, errHistoricalScannerCallback) {
			t.Errorf("nil after: %v", e)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := j.WithOwnedHistoricalPacketFacts(ctx, func(*os.Root, HistoricalPacketScan) error { return nil }); !errors.Is(e, ErrRunJournalContextDone) {
		t.Fatalf("canceled: %v", e)
	}
	if e := j.Close(); e != nil {
		t.Fatal(e)
	}
	if e := j.WithOwnedHistoricalPacketFacts(context.Background(), func(*os.Root, HistoricalPacketScan) error { return nil }); !errors.Is(e, ErrRunJournalClosed) {
		t.Fatalf("closed: %v", e)
	}
}

func TestRootedInventoryWitnessAndCallbackError(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rooted scanner is Linux-only")
	}
	root := filepath.Join(t.TempDir(), "journal")
	j, _ := rootedHistoricalPacketFixture(t, root, "witness")
	plan := inventoryPlan(t, "historical-tenant", "historical-repo", "witness")
	path := j.planPath(plan.Scope())
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := os.WriteFile(path, original, 0600); e != nil {
			t.Error(e)
		}
	})
	called := 0
	e = j.WithOwnedHistoricalPacketFacts(context.Background(), func(_ *os.Root, scan HistoricalPacketScan) error {
		return scan(context.Background(), func(facts []HistoricalContextPacketFact) error {
			called++
			if len(facts) != 1 {
				t.Errorf("provisional facts: %d", len(facts))
			}
			changed := append([]byte(nil), original...)
			changed[len(changed)-2] ^= 1
			if e := os.WriteFile(path, changed, 0600); e != nil {
				return e
			}
			return ErrPreparedContextPacketAtStartup
		})
	})
	if called != 1 || !errors.Is(e, ErrInvalidStartupInventoryEntry) || !errors.Is(e, errHistoricalScannerCallback) || errors.Is(e, ErrPreparedContextPacketAtStartup) {
		t.Fatalf("changed witness and callback: called=%d err=%v", called, e)
	}
}

func TestRootedInventoryLateScopeCorruptionAndLinkShape(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rooted scanner is Linux-only")
	}
	root := filepath.Join(t.TempDir(), "journal")
	j, _ := rootedHistoricalPacketFixture(t, root, "historical")
	later := inventoryPlan(t, "other", "repo", "later")
	inventoryOpen(t, j, later)
	stream := j.streamPath(later.Scope())
	if e := os.WriteFile(stream, []byte("invalid\n"), 0600); e != nil {
		t.Fatal(e)
	}
	called := 0
	inspect := func() error {
		return j.WithOwnedHistoricalPacketFacts(context.Background(), func(_ *os.Root, scan HistoricalPacketScan) error {
			return scan(context.Background(), func([]HistoricalContextPacketFact) error { called++; return nil })
		})
	}
	if e := inspect(); !errors.Is(e, ErrCorruptRunJournalStream) || called != 0 {
		t.Fatalf("late invalid stream: calls=%d err=%v", called, e)
	}
	if e := os.Remove(stream); e != nil {
		t.Fatal(e)
	}
	owner := filepath.Join(root, ".local-source-owner.json")
	extra := filepath.Join(filepath.Dir(root), "outside-owner-link")
	if e := os.Link(owner, extra); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.Remove(extra) })
	if e := inspect(); !errors.Is(e, ErrInvalidStartupInventoryEntry) || called != 0 {
		t.Fatalf("linked owner: calls=%d err=%v", called, e)
	}
	if e := os.Remove(extra); e != nil {
		t.Fatal(e)
	}
	link := stream // a recognized digest-named leaf, not an unknown extra name
	if e := os.Symlink(filepath.Base(j.planPath(later.Scope())), link); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	if e := inspect(); !errors.Is(e, ErrInvalidStartupInventoryEntry) || called != 0 {
		t.Fatalf("symlink: calls=%d err=%v", called, e)
	}
}

func TestRootedInventoryCloseAnnouncementDuringAfter(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rooted scanner is Linux-only")
	}
	root := filepath.Join(t.TempDir(), "journal")
	j, _ := rootedHistoricalPacketFixture(t, root, "closing")
	finished := make(chan error, 1)
	e := j.WithOwnedHistoricalPacketFacts(context.Background(), func(_ *os.Root, scan HistoricalPacketScan) error {
		return scan(context.Background(), func([]HistoricalContextPacketFact) error {
			go func() { finished <- j.Close() }()
			select {
			case <-j.closingSignal:
				return nil
			case <-time.After(5 * time.Second):
				return errors.New("close announcement timed out")
			}
		})
	})
	select {
	case closeErr := <-finished:
		if closeErr != nil {
			t.Error(closeErr)
		}
	case <-time.After(5 * time.Second):
		t.Error("close completion timed out")
	}
	if !errors.Is(e, ErrRunJournalClosed) {
		t.Fatalf("close announced: %v", e)
	}
}

func TestRootedInventoryFinalEntryAndContextChecks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rooted scanner is Linux-only")
	}
	for _, kind := range []string{"valid-prefix-tail", "new-sibling", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "journal")
			j, _ := rootedHistoricalPacketFixture(t, root, "postcheck")
			plan := inventoryPlan(t, "historical-tenant", "historical-repo", "postcheck")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := 0
			e := j.WithOwnedHistoricalPacketFacts(context.Background(), func(_ *os.Root, scan HistoricalPacketScan) error {
				return scan(ctx, func([]HistoricalContextPacketFact) error {
					called++
					switch kind {
					case "valid-prefix-tail":
						f, e := os.OpenFile(j.streamPath(plan.Scope()), os.O_APPEND|os.O_WRONLY, 0)
						if e != nil {
							return e
						}
						_, e = f.Write([]byte("\n"))
						return errors.Join(e, f.Close())
					case "new-sibling":
						return os.Mkdir(filepath.Join(root, "setup"), 0700)
					case "cancel":
						cancel()
					}
					return nil
				})
			})
			if called != 1 || e == nil {
				t.Fatalf("final %s calls=%d err=%v", kind, called, e)
			}
			if kind == "cancel" && !errors.Is(e, ErrRunJournalContextDone) {
				t.Fatalf("cancel error: %v", e)
			}
			if kind != "cancel" && !errors.Is(e, ErrInvalidStartupInventoryEntry) {
				t.Fatalf("witness error: %v", e)
			}
		})
	}
}

func TestRootedInventoryConcurrentScannerUse(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rooted scanner is Linux-only")
	}
	root := filepath.Join(t.TempDir(), "journal")
	j, _ := rootedHistoricalPacketFixture(t, root, "one-use")
	e := j.WithOwnedHistoricalPacketFacts(context.Background(), func(_ *os.Root, scan HistoricalPacketScan) error {
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		finished := make(chan error, 1)
		go func() {
			finished <- scan(context.Background(), func([]HistoricalContextPacketFact) error {
				close(entered)
				select {
				case <-release:
					return nil
				case <-time.After(5 * time.Second):
					return errors.New("scanner after timed out")
				}
			})
		}()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			unblock()
			return errors.New("scanner admission timed out")
		}
		duplicateDone := make(chan error, 1)
		go func() {
			duplicateDone <- scan(context.Background(), func([]HistoricalContextPacketFact) error {
				return errors.New("second scanner callback ran")
			})
		}()
		var duplicate error
		select {
		case duplicate = <-duplicateDone:
		case <-time.After(5 * time.Second):
			unblock()
			return errors.New("concurrent scanner rejection timed out")
		}
		unblock()
		if !errors.Is(duplicate, errHistoricalScannerUnavailable) {
			return fmt.Errorf("concurrent scanner admitted: %v", duplicate)
		}
		select {
		case e := <-finished:
			return e
		case <-time.After(5 * time.Second):
			return errors.New("admitted scanner completion timed out")
		}
	})
	if e != nil {
		t.Fatal(e)
	}
}
