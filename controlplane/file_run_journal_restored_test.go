package controlplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Offline replay must preserve closed bytes and refuse missing lock authority.
func TestRestoredJournalInspectionDoesNotAcquireWriterAuthority(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := inventoryPlan(t, "tenant-a", "repo-a", "restore-run")
	coordinator := inventoryOpen(t, journal, plan)
	if _, err := coordinator.CancelRun(context.Background(), plan, time.UnixMilli(200)); err != nil {
		t.Fatal(err)
	}
	expected, err := coordinator.Receipt(context.Background(), plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	before := restoredJournalLeaves(t, root)
	receipts, err := InspectRestoredJournal(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || receipts[0].Identity() != expected.Identity() {
		t.Fatalf("terminal replay mismatch: %v", receipts)
	}
	if after := restoredJournalLeaves(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("offline replay changed journal leaves")
	}
	if err := os.Remove(filepath.Join(root, runJournalWriterLockName)); err != nil {
		t.Fatal(err)
	}
	before = restoredJournalLeaves(t, root)
	if _, err := InspectRestoredJournal(context.Background(), root); err == nil {
		t.Fatal("missing cooperative lock accepted")
	}
	if after := restoredJournalLeaves(t, root); !reflect.DeepEqual(before, after) {
		t.Fatal("reader recreated or repaired missing authority")
	}
}

type restoredLeaf struct {
	Mode   os.FileMode
	Size   int64
	Digest [32]byte
}

func restoredJournalLeaves(t *testing.T, root string) map[string]restoredLeaf {
	t.Helper()
	result := map[string]restoredLeaf{}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() {
			t.Fatal("unexpected fixture entry")
		}
		content, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = restoredLeaf{info.Mode(), info.Size(), sha256.Sum256(content)}
	}
	return result
}

func TestRestoredJournalRefusesActiveWriterAndUncertainOrCorruptHistory(t *testing.T) {
	for _, testcase := range []string{"writer", "intent", "corrupt", "incomplete"} {
		t.Run(testcase, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "journal")
			journal, err := NewFileRunJournal(root)
			if err != nil {
				t.Fatal(err)
			}
			plan := inventoryPlan(t, "tenant-a", "repo-a", "restore-run")
			coordinator := inventoryOpen(t, journal, plan)
			if _, err := coordinator.CancelRun(context.Background(), plan, time.UnixMilli(200)); err != nil {
				t.Fatal(err)
			}
			if testcase == "writer" {
				defer journal.Close()
				before := restoredJournalLeaves(t, root)
				receipts, err := InspectRestoredJournal(context.Background(), root)
				if !errors.Is(err, ErrRunJournalLocked) || receipts != nil {
					t.Fatalf("active writer accepted: %v", err)
				}
				if !reflect.DeepEqual(before, restoredJournalLeaves(t, root)) {
					t.Fatal("active writer refusal changed bytes")
				}
				return
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}
			var want error
			switch testcase {
			case "intent":
				want = ErrScopeIntentUnresolved
				if err := os.WriteFile(filepath.Join(root, strings.Repeat("a", 64)+scopeIntentSuffix), []byte("uncertain"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				want = ErrCorruptRunJournalStream
				if err := os.WriteFile(filepath.Join(root, plan.Scope().Identity()+runJournalStreamSuffix), []byte("invalid\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "incomplete":
				want = ErrIncompleteStartupInventoryPrefix
				if err := os.Remove(filepath.Join(root, plan.Scope().Identity()+runJournalStreamSuffix)); err != nil {
					t.Fatal(err)
				}
			}
			before := restoredJournalLeaves(t, root)
			receipts, err := InspectRestoredJournal(context.Background(), root)
			if !errors.Is(err, want) || receipts != nil {
				t.Fatalf("refusal = %v, want %v", err, want)
			}
			if !reflect.DeepEqual(before, restoredJournalLeaves(t, root)) {
				t.Fatal("refusal modified uncertain bytes")
			}
		})
	}
}

func TestRestoredJournalRefusesReplacedLockedLeaf(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := inventoryPlan(t, "tenant-a", "repo-a", "restore-lock")
	inventoryOpen(t, journal, plan)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	receipts, err := inspectRestoredJournal(context.Background(), root, func() error {
		path := filepath.Join(root, runJournalWriterLockName)
		if err := os.Remove(path); err != nil {
			return err
		}
		return os.WriteFile(path, nil, 0o600)
	})
	if receipts != nil || !errors.Is(err, ErrInvalidStartupInventoryEntry) {
		t.Fatalf("orphan lock accepted: %v", err)
	}
}

func TestRestoredJournalRefusesSymlinkAncestor(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "parent")
	if err := os.Symlink(parent, link); err != nil {
		t.Fatal(err)
	}
	before := restoredJournalLeaves(t, root)
	receipts, err := InspectRestoredJournal(context.Background(), filepath.Join(link, "journal"))
	if receipts != nil || !errors.Is(err, ErrInvalidRunJournalRoot) {
		t.Fatalf("symlink ancestry accepted: %v", err)
	}
	if !reflect.DeepEqual(before, restoredJournalLeaves(t, root)) {
		t.Fatal("ancestor refusal changed bytes")
	}
}

func TestRestoredJournalRetainsFenceAcrossObservation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := inventoryPlan(t, "tenant-a", "repo-a", "held-restore")
	inventoryOpen(t, journal, plan)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	err = WithRestoredJournal(context.Background(), root, func(borrowed *os.Root, receipts []ReviewRunReceipt) error {
		if borrowed == nil || len(receipts) != 1 {
			t.Fatal("missing borrowed observation")
		}
		writer, err := NewFileRunJournal(root)
		if writer != nil {
			writer.Close()
		}
		if !errors.Is(err, ErrRunJournalLocked) {
			t.Fatalf("journal fence released inside observer: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func TestRestoredJournalRechecksAfterObservation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := inventoryPlan(t, "tenant-a", "repo-a", "changed-restore")
	inventoryOpen(t, journal, plan)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	err = WithRestoredJournal(context.Background(), root, func(_ *os.Root, _ []ReviewRunReceipt) error {
		path := filepath.Join(root, plan.Scope().Identity()+runJournalStreamSuffix)
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		// Keep inode, mode and length unchanged so only the digest witness can detect this.
		content[0] ^= 1
		return os.WriteFile(path, content, 0o600)
	})
	if !errors.Is(err, ErrInvalidStartupInventoryEntry) {
		t.Fatalf("changed observed bytes accepted: %v", err)
	}
}

func TestRestoredJournalRetainsObservationAndWitnessErrors(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	plan := inventoryPlan(t, "tenant-a", "repo-a", "faulted-observer")
	inventoryOpen(t, journal, plan)
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	observationErr := errors.New("observer failure")
	err = WithRestoredJournal(context.Background(), root, func(_ *os.Root, _ []ReviewRunReceipt) error {
		path := filepath.Join(root, plan.Scope().Identity()+runJournalStreamSuffix)
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content[0] ^= 1
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return err
		}
		return observationErr
	})
	if !errors.Is(err, observationErr) || !errors.Is(err, ErrInvalidStartupInventoryEntry) {
		t.Fatalf("independent observation or drift error lost: %v", err)
	}
}
