package controlplane

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

var _ func(*FileRunJournal, context.Context, func(*os.Root, HistoricalPacketScan) error) error = (*FileRunJournal).WithOwnedHistoricalPacketFacts

func rootedHistoricalPacketFixture(t *testing.T, root, run string) (*FileRunJournal, HistoricalContextPacketFact) {
	t.Helper()
	ctx := context.Background()
	journal, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	})
	plan := inventoryPlan(t, "historical-tenant", "historical-repo", run)
	coordinator := inventoryOpen(t, journal, plan)
	lease := inventoryPreparedLease(t, coordinator, plan)
	prepared, err := coordinator.PrepareContextPacket(ctx, plan, lease, historicalDescriptor(plan, lease), lease.ExpiresAt().Add(-2*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.TerminatePreparedContextPacket(ctx, plan, prepared, lease.ExpiresAt().Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.CancelRun(ctx, plan, lease.ExpiresAt().Add(2*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	// The diagnostic scanner checks owner shape, not startup owner-record contents.
	if err := os.WriteFile(filepath.Join(root, ".local-source-owner.json"), []byte("fixture-owner\n"), 0600); err != nil {
		t.Fatal(err)
	}
	facts, err := journal.InspectHistoricalContextPackets(ctx)
	if err != nil || len(facts) != 1 || facts[0].PreparedEvent().Identity() != prepared.Identity() {
		t.Fatalf("fixture fact count=%d err=%v", len(facts), err)
	}
	return journal, facts[0]
}

func TestRootedHistoricalPacketStableOriginalFact(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rooted historical packet scanner is Linux-only")
	}
	root := filepath.Join(t.TempDir(), "journal")
	journal, original := rootedHistoricalPacketFixture(t, root, "original")

	calls := 0
	err := journal.WithOwnedHistoricalPacketFacts(context.Background(), func(_ *os.Root, scan HistoricalPacketScan) error {
		return scan(context.Background(), func(facts []HistoricalContextPacketFact) error {
			calls++
			if len(facts) != 1 || !reflect.DeepEqual(facts[0], original) {
				t.Errorf("scanner did not deliver exactly the original historical fact: %+v", facts)
			}
			return nil
		})
	})
	if err != nil || calls != 1 {
		t.Fatalf("stable rooted scan: calls=%d err=%v", calls, err)
	}
}

func TestRootedHistoricalPacketSwapNeverDeliversReplacement(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rooted historical packet scanner is Linux-only")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "journal")
	aside := filepath.Join(parent, "journal-original")
	replacementPath := filepath.Join(parent, "journal-replacement")
	journal, original := rootedHistoricalPacketFixture(t, root, "original")
	replacement, replacementFact := rootedHistoricalPacketFixture(t, replacementPath, "replacement")
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	originalID := original.PreparedEvent().Identity()
	replacementID := replacementFact.PreparedEvent().Identity()
	if originalID == replacementID || original.Plan().Identity() == replacementFact.Plan().Identity() {
		t.Fatal("fixtures are not distinct")
	}

	movedOriginal, installedReplacement := false, false
	t.Cleanup(func() {
		if installedReplacement {
			if err := os.Rename(root, replacementPath); err != nil {
				t.Errorf("remove installed replacement: %v", err)
			}
		}
		if movedOriginal {
			if err := os.Rename(aside, root); err != nil {
				t.Errorf("restore original root before journal close: %v", err)
			}
		}
	})
	seen := 0
	err := journal.WithOwnedHistoricalPacketFacts(context.Background(), func(_ *os.Root, scan HistoricalPacketScan) error {
		if renameErr := os.Rename(root, aside); renameErr != nil {
			return renameErr
		}
		movedOriginal = true
		if renameErr := os.Rename(replacementPath, root); renameErr != nil {
			return renameErr
		}
		installedReplacement = true
		legacy, legacyErr := journal.InspectHistoricalContextPackets(context.Background())
		if legacyErr != nil || len(legacy) != 1 || !reflect.DeepEqual(legacy[0], replacementFact) {
			t.Errorf("legacy pathname inspection did not see replacement: count=%d err=%v", len(legacy), legacyErr)
		}
		return scan(context.Background(), func(facts []HistoricalContextPacketFact) error {
			seen++
			if len(facts) != 1 || !reflect.DeepEqual(facts[0], original) {
				t.Errorf("rooted scanner delivered non-original facts: %+v", facts)
			}
			return nil
		})
	})
	if seen > 1 || (err == nil && seen != 1) {
		t.Errorf("swap scan must refuse or deliver one original fact: callbacks=%d err=%v", seen, err)
	}
	if err == nil {
		t.Error("journal root postcheck accepted pathname replacement")
	}
}
