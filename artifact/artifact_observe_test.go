package artifact

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

	"github.com/georgejieh/open-trestle/audit"
)

// observerArtifactFixture builds a private store root, a scope and one valid
// artifact without opening a writer and without a writer lock leaf.
func observerArtifactFixture(t *testing.T) (string, audit.ReviewScope, Artifact, []byte) {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	value, err := New(scope, KindSourceSnapshot, "application/json", ClassificationPublic, OriginHost, ProtectionProcessPrivate,
		[]string{strings.Repeat("a", 64)}, []byte("observed payload"), time.UnixMilli(1000), time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory, scope, value, encoded
}

type observerArtifactLeaf struct {
	Mode   os.FileMode
	Size   int64
	Digest [32]byte
}

func observerArtifactDirectoryState(t *testing.T, directory string) map[string]observerArtifactLeaf {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	state := map[string]observerArtifactLeaf{}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		state[entry.Name()] = observerArtifactLeaf{info.Mode(), info.Size(), sha256.Sum256(content)}
	}
	return state
}

func TestObserveFileArtifactReadsLeafWithoutWriterOrMutation(t *testing.T) {
	directory, scope, expected, encoded := observerArtifactFixture(t)
	path := filepath.Join(directory, artifactFileName(scope, expected.Identity()))
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	before := observerArtifactDirectoryState(t, directory)
	observed, err := ObserveFileArtifact(context.Background(), root, scope, expected.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if observed.Identity() != expected.Identity() || observed.PayloadDigest() != expected.PayloadDigest() {
		t.Fatalf("observed identity mismatch: %v", observed.Identity())
	}
	if observed.Scope().Identity() != scope.Identity() {
		t.Fatalf("observed scope mismatch: %v", observed.Scope().Identity())
	}
	if after := observerArtifactDirectoryState(t, directory); !reflect.DeepEqual(before, after) {
		t.Fatal("observation changed the store")
	}
	if _, err := os.Lstat(filepath.Join(directory, artifactLockName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("observation created a writer lock: %v", err)
	}
}

func TestObserveFileArtifactReportsMissingLeaf(t *testing.T) {
	directory, scope, expected, _ := observerArtifactFixture(t)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := ObserveFileArtifact(context.Background(), root, scope, expected.Identity()); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("missing leaf accepted: %v", err)
	}
}

func TestObserveFileArtifactReportsRootFailureBeforeAbsentLeaf(t *testing.T) {
	directory, scope, expected, _ := observerArtifactFixture(t)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// The leaf is absent and the root mode changes inside the observation. The
	// root failure must be reported instead of the expected absence.
	observed, err := observeFileArtifact(context.Background(), root, scope, expected.Identity(), func() error {
		return os.Chmod(directory, 0o755)
	}, (*os.File).Close)
	if !errors.Is(err, ErrInvalidStoreRoot) {
		t.Fatalf("root failure reported as leaf absence: %v %v", observed.Identity(), err)
	}
}

func TestObserveFileArtifactRefusesCorruptBytes(t *testing.T) {
	directory, scope, expected, _ := observerArtifactFixture(t)
	path := filepath.Join(directory, artifactFileName(scope, expected.Identity()))
	if err := os.WriteFile(path, []byte("not a canonical artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := ObserveFileArtifact(context.Background(), root, scope, expected.Identity()); !errors.Is(err, ErrCorruptArtifact) {
		t.Fatalf("corrupt leaf accepted: %v", err)
	}
}

func TestObserveFileArtifactRefusesChangedBytes(t *testing.T) {
	directory, scope, expected, encoded := observerArtifactFixture(t)
	path := filepath.Join(directory, artifactFileName(scope, expected.Identity()))
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	observed, err := observeFileArtifact(context.Background(), root, scope, expected.Identity(), func() error {
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		content[0] ^= 1
		return os.WriteFile(path, content, 0o600)
	}, (*os.File).Close)
	if !errors.Is(err, ErrCorruptArtifact) {
		t.Fatalf("changed bytes accepted: %v %v", observed.Identity(), err)
	}
}
