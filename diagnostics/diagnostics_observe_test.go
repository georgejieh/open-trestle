package diagnostics

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
)

// observerSetFixture builds a private store root, a scope and one valid diagnostic
// set without opening a writer and without a writer lock leaf.
func observerSetFixture(t *testing.T) (string, audit.ReviewScope, Set, []byte) {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	value, err := NewSet(scope, strings.Repeat("b", 64), strings.Repeat("1", 40), strings.Repeat("c", 64), nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeSet(value)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory, scope, value, encoded
}

type observerSetLeaf struct {
	Mode   os.FileMode
	Size   int64
	Digest [32]byte
}

func observerSetDirectoryState(t *testing.T, directory string) map[string]observerSetLeaf {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	state := map[string]observerSetLeaf{}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		state[entry.Name()] = observerSetLeaf{info.Mode(), info.Size(), sha256.Sum256(content)}
	}
	return state
}

func TestObserveFileSetReadsLeafWithoutWriterOrMutation(t *testing.T) {
	directory, scope, expected, encoded := observerSetFixture(t)
	path := filepath.Join(directory, diagnosticSetFileName(scope))
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	before := observerSetDirectoryState(t, directory)
	observed, err := ObserveFileSet(context.Background(), root, scope)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Identity() != expected.Identity() {
		t.Fatalf("observed identity mismatch: %v", observed.Identity())
	}
	if observed.Scope().Identity() != scope.Identity() {
		t.Fatalf("observed scope mismatch: %v", observed.Scope().Identity())
	}
	if after := observerSetDirectoryState(t, directory); !reflect.DeepEqual(before, after) {
		t.Fatal("observation changed the store")
	}
	if _, err := os.Lstat(filepath.Join(directory, diagnosticLockName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("observation created a writer lock: %v", err)
	}
}

func TestObserveFileSetReportsMissingLeaf(t *testing.T) {
	directory, scope, _, _ := observerSetFixture(t)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := ObserveFileSet(context.Background(), root, scope); !errors.Is(err, ErrSetNotFound) {
		t.Fatalf("missing leaf accepted: %v", err)
	}
}

func TestObserveFileSetReportsRootFailureBeforeAbsentLeaf(t *testing.T) {
	directory, scope, _, _ := observerSetFixture(t)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// The leaf is absent and the root mode changes inside the observation. The
	// root failure must be reported instead of the expected absence.
	observed, err := observeFileSet(context.Background(), root, scope, func() error {
		return os.Chmod(directory, 0o755)
	}, (*os.File).Close)
	if !errors.Is(err, ErrInvalidStoreRoot) {
		t.Fatalf("root failure reported as leaf absence: %v %v", observed.Identity(), err)
	}
}

func TestObserveFileSetRefusesCorruptBytes(t *testing.T) {
	directory, scope, _, _ := observerSetFixture(t)
	path := filepath.Join(directory, diagnosticSetFileName(scope))
	if err := os.WriteFile(path, []byte("not a canonical set"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := ObserveFileSet(context.Background(), root, scope); !errors.Is(err, ErrCorruptStoreRecord) {
		t.Fatalf("corrupt leaf accepted: %v", err)
	}
}

func TestObserveFileSetRefusesChangedBytes(t *testing.T) {
	directory, scope, _, encoded := observerSetFixture(t)
	path := filepath.Join(directory, diagnosticSetFileName(scope))
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	observed, err := observeFileSet(context.Background(), root, scope, func() error {
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		content[0] ^= 1
		return os.WriteFile(path, content, 0o600)
	}, (*os.File).Close)
	if !errors.Is(err, ErrCorruptStoreRecord) {
		t.Fatalf("changed bytes accepted: %v %v", observed.Identity(), err)
	}
}
