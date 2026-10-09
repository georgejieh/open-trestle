package artifact

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

func TestFileStorePacketPutPostRenameErrorRetainsVisibleBytesAfterReopen(t *testing.T) {
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	value := artifactFixture(t, scope, `{"packet":"private"}`)
	expected, err := Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	injected := errors.New("injected after artifact rename")
	calls := 0
	// This instance has no concurrent operations; persist also writes deletion records.
	store.afterPersistRename = func() error {
		calls++
		return injected
	}
	created, putErr := store.Put(context.Background(), value, time.UnixMilli(200))
	store.afterPersistRename = nil
	if calls != 1 || created || !errors.Is(putErr, ErrStorePersistence) || !errors.Is(putErr, injected) {
		t.Fatalf("post-rename put: calls=%d created=%t err=%v", calls, created, putErr)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened store: %v", err)
		}
	}()
	got, err := reopened.Get(context.Background(), scope, value.Identity(), time.UnixMilli(300))
	if err != nil {
		t.Fatal(err)
	}
	if got.Identity() != value.Identity() || got.Scope().Identity() != scope.Identity() || got.PayloadDigest() != value.PayloadDigest() || got.Protection() != ProtectionProcessPrivate || got.Kind() != KindContextPacket {
		t.Fatalf("reopened packet differs: got=%#v want=%#v", got, value)
	}
	encoded, err := Encode(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, expected) {
		t.Fatal("reopened packet envelope differs")
	}
	physical, err := os.ReadFile(reopened.artifactPath(scope, value.Identity()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(physical, expected) {
		t.Fatal("reopened packet physical bytes differ")
	}
}
