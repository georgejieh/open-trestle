package artifact

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

func TestPendingFileStoreHoldsLockUntilClosed(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-pending")
	root := filepath.Join(t.TempDir(), "artifacts")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	value := artifactFixture(t, scope, `{"pending":true}`)
	if _, err := store.Put(context.Background(), value, time.UnixMilli(200)); err != nil {
		t.Fatal(err)
	}
	payloadPath := store.artifactPath(scope, value.Identity())
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	pending, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := any(pending).(Store); ok {
		t.Fatal("pending implements Store")
	}
	competing, err := NewFileStore(root)
	if competing != nil || !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("competing=(%v,%v)", competing, err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if activated, err := pending.Activate(); activated != nil || !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("closed activation=(%v,%v)", activated, err)
	}
	if got, err := os.ReadFile(payloadPath); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("payload changed: %v", err)
	}
	reopened, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
}

func TestPendingFileStoreActivationTransfersLock(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-transfer")
	root := filepath.Join(t.TempDir(), "artifacts")
	pending, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	active, err := pending.Activate()
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if again, err := pending.Activate(); again != nil || !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("second activation=(%v,%v)", again, err)
	}
	competing, err := NewFileStore(root)
	if competing != nil || !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("lock transferred=(%v,%v)", competing, err)
	}
	fresh := artifactFixture(t, scope, `{"fresh":true}`)
	if created, err := active.Put(context.Background(), fresh, time.UnixMilli(200)); !created || err != nil {
		t.Fatalf("put=(%v,%v)", created, err)
	}
	gotValue, err := active.Get(context.Background(), scope, fresh.Identity(), time.UnixMilli(200))
	if err != nil || gotValue.Identity() != fresh.Identity() {
		t.Fatalf("get=(%v,%v)", gotValue, err)
	}
	if err := active.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
}

func TestPendingFileStoreValueCopiesShareLockTransfer(t *testing.T) {
	root := filepath.Join(t.TempDir(), "artifacts")
	pending, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	clone := *pending
	active, err := clone.Activate()
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if again, err := pending.Activate(); again != nil || !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("second activation=(%v,%v)", again, err)
	}
	if again, err := clone.Activate(); again != nil || !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("clone activation=(%v,%v)", again, err)
	}
	competing, err := OpenPendingFileStore(root)
	if competing != nil {
		_ = competing.Close()
	}
	if competing != nil || !errors.Is(err, ErrStoreLocked) {
		t.Fatalf("active owner lost lock=(%v,%v)", competing, err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-copy")
	value := artifactFixture(t, scope, `{"copy":true}`)
	if created, err := active.Put(context.Background(), value, time.UnixMilli(200)); !created || err != nil {
		t.Fatalf("active put=(%v,%v)", created, err)
	}
	got, err := active.Get(context.Background(), scope, value.Identity(), time.UnixMilli(200))
	if err != nil || got.Identity() != value.Identity() {
		t.Fatalf("active get=(%v,%v)", got, err)
	}
}

func TestPendingFileStoreActivateCloseRaceHasAtMostOneOwner(t *testing.T) {
	for i := 0; i < 20; i++ {
		root := filepath.Join(t.TempDir(), "artifacts")
		pending, err := OpenPendingFileStore(root)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		var active *FileStore
		var activationErr, closeErr error
		go func() { defer wait.Done(); <-start; active, activationErr = pending.Activate() }()
		go func() { defer wait.Done(); <-start; closeErr = pending.Close() }()
		close(start)
		wait.Wait()
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		if active == nil {
			if !errors.Is(activationErr, ErrStoreClosed) {
				t.Fatalf("failed activation: %v", activationErr)
			}
		} else {
			if activationErr != nil {
				t.Fatal(activationErr)
			}
			competing, err := OpenPendingFileStore(root)
			if competing != nil || !errors.Is(err, ErrStoreLocked) {
				t.Fatalf("active owner lost lock: %v, %v", competing, err)
			}
			if err := active.Close(); err != nil {
				t.Fatal(err)
			}
		}
		reopened, err := OpenPendingFileStore(root)
		if err != nil {
			t.Fatal(err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPendingFileStoreActivationRejectsReplacedRoot(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-replaced")
	root := filepath.Join(t.TempDir(), "artifacts")
	original, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	value := artifactFixture(t, scope, `{}`)
	if _, err := original.Put(context.Background(), value, time.UnixMilli(200)); err != nil {
		t.Fatal(err)
	}
	payloadPath := original.artifactPath(scope, value.Identity())
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	pending, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	moved := root + "-moved"
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	replacementScope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-replacement")
	replacementValue := artifactFixture(t, replacementScope, `{"replacement":true}`)
	replacementPayload, err := Encode(replacementValue)
	if err != nil {
		t.Fatal(err)
	}
	replacementPayloadPath := original.artifactPath(replacementScope, replacementValue.Identity())
	if err := os.WriteFile(replacementPayloadPath, replacementPayload, 0o600); err != nil {
		t.Fatal(err)
	}
	active, err := pending.Activate()
	if active != nil || !errors.Is(err, ErrInvalidStoreRoot) {
		t.Fatalf("replaced activation=(%v,%v)", active, err)
	}
	for _, file := range []struct {
		path string
		want []byte
	}{
		{filepath.Join(moved, filepath.Base(payloadPath)), payload},
		{replacementPayloadPath, replacementPayload},
	} {
		got, err := os.ReadFile(file.path)
		if err != nil || !bytes.Equal(got, file.want) {
			t.Fatalf("activation changed %s: %v", file.path, err)
		}
	}
	if again, err := pending.Activate(); again != nil || !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("second activation=(%v,%v)", again, err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, root+"-replacement"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, root); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatalf("moved original writer lock not released: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}
