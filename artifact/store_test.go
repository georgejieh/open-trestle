package artifact

import (
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func artifactFixture(t *testing.T, scope audit.ReviewScope, payload string) Artifact {
	t.Helper()
	value, err := New(scope, KindContextPacket, "application/json", ClassificationConfidential, OriginHost, ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, []byte(payload), time.UnixMilli(100), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func TestMemoryStoreEnforcesScopeExpiryAndProtection(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	store, err := NewMemoryStore(ProtectionProcessPrivate, 10)
	if err != nil {
		t.Fatal(err)
	}
	value := artifactFixture(t, scope, `{}`)
	created, err := store.Put(context.Background(), value, time.UnixMilli(200))
	if err != nil || !created {
		t.Fatalf("put=(%t,%v)", created, err)
	}
	got, err := store.Get(context.Background(), scope, value.Identity(), time.UnixMilli(300))
	if err != nil || got.Identity() != value.Identity() {
		t.Fatalf("get=(%#v,%v)", got, err)
	}
	other, _ := audit.NewReviewScope("tenant-b", "repo-a", "run-a")
	if got, err := store.Get(context.Background(), other, value.Identity(), time.UnixMilli(300)); !errors.Is(err, ErrArtifactNotFound) || got.Identity() != "" {
		t.Fatalf("cross scope=(%#v,%v)", got, err)
	}
	if got, err := store.Get(context.Background(), scope, value.Identity(), time.UnixMilli(1001)); !errors.Is(err, ErrArtifactExpired) || got.Identity() != "" {
		t.Fatalf("expired=(%#v,%v)", got, err)
	}
}
func TestFileStorePersistsPrivateArtifactAndRejectsCorruption(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	root := filepath.Join(t.TempDir(), "artifacts")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	value := artifactFixture(t, scope, `{"large":"value"}`)
	created, err := store.Put(context.Background(), value, time.UnixMilli(200))
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
	got, err := reopened.Get(context.Background(), scope, value.Identity(), time.UnixMilli(300))
	if err != nil || got.Identity() != value.Identity() {
		t.Fatalf("get=(%#v,%v)", got, err)
	}
	information, err := os.Stat(reopened.artifactPath(scope, value.Identity()))
	if err != nil || information.Mode().Perm() != 0o600 {
		t.Fatalf("file=(%v,%v)", information, err)
	}
	if err := os.WriteFile(reopened.artifactPath(scope, value.Identity()), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.Get(context.Background(), scope, value.Identity(), time.UnixMilli(300)); !errors.Is(err, ErrCorruptArtifact) || got.Identity() != "" {
		t.Fatalf("corrupt=(%#v,%v)", got, err)
	}
}
