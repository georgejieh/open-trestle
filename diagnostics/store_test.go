package diagnostics

import (
	"context"
	"errors"
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
