package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
)

func diagnosticSetFixture(t *testing.T) Set { t.Helper(); return mustDiagnosticSet(t, "run-a", nil) }
func mustDiagnosticSet(t *testing.T, runID string, findings []Finding) Set {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", runID)
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewSet(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), findings)
	if err != nil {
		t.Fatal(err)
	}
	return set
}
func TestMemoryStoreSerializesImmutableSet(t *testing.T) {
	store := NewMemoryStore()
	set := diagnosticSetFixture(t)
	var created atomic.Int32
	var failures atomic.Int32
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			wasCreated, err := store.PutDiagnosticSet(context.Background(), set)
			if err != nil {
				failures.Add(1)
			}
			if wasCreated {
				created.Add(1)
			}
		}()
	}
	wait.Wait()
	if created.Load() != 1 || failures.Load() != 0 {
		t.Fatalf("created=%d failures=%d", created.Load(), failures.Load())
	}
	got, err := store.GetDiagnosticSet(context.Background(), set.Scope())
	if err != nil || got.Identity() != set.Identity() {
		t.Fatalf("get=(%#v,%v)", got, err)
	}
}
func TestFileStorePersistsAndDetectsConflicts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "diagnostics")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	set := diagnosticSetFixture(t)
	created, err := store.PutDiagnosticSet(context.Background(), set)
	if err != nil || !created {
		t.Fatalf("put=(%t,%v)", created, err)
	}
	if competing, err := NewFileStore(root); !errors.Is(err, ErrStoreLocked) || competing != nil {
		t.Fatalf("competing=(%#v,%v)", competing, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	created, err = reopened.PutDiagnosticSet(context.Background(), set)
	if err != nil || created {
		t.Fatalf("duplicate=(%t,%v)", created, err)
	}
	got, err := reopened.GetDiagnosticSet(context.Background(), set.Scope())
	if err != nil || got.Identity() != set.Identity() {
		t.Fatalf("get=(%#v,%v)", got, err)
	}
	information, err := os.Stat(reopened.setPath(set.Scope()))
	if err != nil || information.Mode().Perm() != 0o600 {
		t.Fatalf("file=(%v,%v)", information, err)
	}
}
func TestFileStoreDetectsCorruptRecord(t *testing.T) {
	root := filepath.Join(t.TempDir(), "diagnostics")
	store, _ := NewFileStore(root)
	defer store.Close()
	set := diagnosticSetFixture(t)
	_, _ = store.PutDiagnosticSet(context.Background(), set)
	if err := os.WriteFile(store.setPath(set.Scope()), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetDiagnosticSet(context.Background(), set.Scope()); !errors.Is(err, ErrCorruptStoreRecord) || got.Identity() != "" {
		t.Fatalf("get=(%#v,%v)", got, err)
	}
}

func deterministicSetAtCount(t *testing.T, runID string, count int) (Set, error) {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", runID)
	analysisIdentity, changeIdentity := strings.Repeat("8", 64), strings.Repeat("7", 64)
	source := DeterministicCheck{changeIdentity: changeIdentity, state: CheckFailed, applicableFiles: 1, applicableRanges: 1, checkedFiles: 1, checkedRanges: 1, matches: uint32(count)}
	check, err := NewDeterministicCheck(deriveSourceDeterministicCheckIdentity(source), analysisIdentity, changeIdentity, CheckFailed, 1, 1, 1, 1, uint32(count))
	if err != nil {
		return Set{}, err
	}
	observations := make([]DeterministicObservation, count)
	for index := range observations {
		observations[index], err = NewDeterministicObservation(fmt.Sprintf("%064x", index+1), fmt.Sprintf("%064x", index+10000), analysisIdentity, check.Identity(), "Debug output left in source", "The deterministic static rule matched this exact changed range; human review is required.", SeverityWarning, fmt.Sprintf("path-%04d.go", index), 1, 1, []string{fmt.Sprintf("%064x", index+20000)})
		if err != nil {
			return Set{}, err
		}
	}
	return NewSetWithDeterministicObservations(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), analysisIdentity, []DeterministicCheck{check}, observations)
}
func TestFileStorePersistsBoundedDeterministicSetAndRejectsOversizedConstruction(t *testing.T) {
	set, err := deterministicSetAtCount(t, "run-bounded", 1000)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeSet(set)
	if err != nil || len(encoded) >= MaxEncodedSetBytes {
		t.Fatalf("bounded encoding=(%d,%v)", len(encoded), err)
	}
	store, err := NewFileStore(filepath.Join(t.TempDir(), "diagnostics"))
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.PutDiagnosticSet(context.Background(), set)
	if err != nil || !created {
		t.Fatalf("put=(%t,%v)", created, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(store.root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, err := reopened.GetDiagnosticSet(context.Background(), set.Scope())
	if err != nil || loaded.Identity() != set.Identity() {
		t.Fatalf("loaded=(%#v,%v)", loaded, err)
	}
	if oversized, err := deterministicSetAtCount(t, "run-oversized", 1500); !errors.Is(err, ErrSetResourceLimit) || oversized.Identity() != "" {
		t.Fatalf("oversized=(%#v,%v)", oversized, err)
	}
}
