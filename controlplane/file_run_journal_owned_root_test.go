package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/filelock"
)

func ownedJournal(t *testing.T) (*FileRunJournal, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	j, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closed := make(chan error, 1)
		go func() { closed <- j.Close() }()
		if err := waitOwnedRootError(t, closed, "journal cleanup"); err != nil {
			t.Error(err)
		}
	})
	return j, root
}

func TestFileRunJournalOwnedRootFreshAndPrivate(t *testing.T) {
	j, root := ownedJournal(t)
	var borrowed *os.Root
	if err := j.WithOwnedRoot(context.Background(), func(r *os.Root) error {
		borrowed = r
		info, err := r.Stat(".")
		if err != nil || info.Mode() != os.ModeDir|0700 {
			t.Fatalf("root=(%v,%v)", info, err)
		}
		_, err = j.InspectStartupInventory(context.Background())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := borrowed.Stat("."); err == nil {
		t.Fatal("borrowed root survived callback")
	}
	if _, err := os.Lstat(root); err != nil {
		t.Fatal(err)
	}
	if err := j.WithOwnedRoot(nil, func(*os.Root) error { t.Fatal("called"); return nil }); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := j.WithOwnedRoot(context.Background(), nil); err == nil {
		t.Fatal("nil callback accepted")
	}
}

func TestFileRunJournalOwnedRootReplacementAndMode(t *testing.T) {
	j, root := ownedJournal(t)
	old := root + "-old"
	if err := os.Rename(root, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := j.WithOwnedRoot(context.Background(), func(*os.Root) error { called = true; return nil }); err == nil || called {
		t.Fatalf("replacement: err=%v called=%v", err, called)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(old, root); err != nil {
		t.Fatal(err)
	}
	if err := j.WithOwnedRoot(context.Background(), func(*os.Root) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := j.WithOwnedRoot(context.Background(), func(*os.Root) error { t.Fatal("called"); return nil }); err == nil {
		t.Fatal("mode accepted")
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
}

func TestFileRunJournalOwnedRootAncestorChanges(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "state")
	j, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	original := parent + "-original"
	if err := os.Rename(parent, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(original, parent); err != nil {
		t.Fatal(err)
	}
	if err := j.WithOwnedRoot(context.Background(), func(*os.Root) error { t.Fatal("symlink accepted"); return nil }); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, parent); err != nil {
		t.Fatal(err)
	}
	callbackErr := errors.New("callback failed")
	var borrowed *os.Root
	err = j.WithOwnedRoot(context.Background(), func(r *os.Root) error {
		borrowed = r
		if err := os.Rename(parent, original); err != nil {
			return err
		}
		if err := os.Mkdir(parent, 0700); err != nil {
			return err
		}
		if err := os.Rename(filepath.Join(original, "state"), root); err != nil {
			return err
		}
		return callbackErr
	})
	if !errors.Is(err, callbackErr) || !errors.Is(err, fileauthority.ErrUntrustedPath) {
		t.Fatalf("changed parent: %v", err)
	}
	if _, err := borrowed.Stat("."); err == nil {
		t.Fatal("post-use error returned before borrowed root close")
	}
	// The original leaf remains in place, but the original parent pin must differ.
	if err := j.WithOwnedRoot(context.Background(), func(*os.Root) error { return nil }); err != nil {
		t.Fatalf("new call should independently pin: %v", err)
	}
}

// These waits fail in bounded time and do not strand a blocked callback.
func waitOwnedRootSignal(t *testing.T, signal <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func waitOwnedRootError(t *testing.T, result <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
}

func TestFileRunJournalOwnedRootCloseWaits(t *testing.T) {
	j, _ := ownedJournal(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	releaseCallback := sync.OnceFunc(func() { close(release) })
	defer releaseCallback()
	go func() {
		done <- j.WithOwnedRoot(context.Background(), func(*os.Root) error { close(entered); <-release; return nil })
	}()
	waitOwnedRootSignal(t, entered, "callback entry")
	closed := make(chan error, 1)
	go func() { closed <- j.Close() }()
	waitOwnedRootSignal(t, j.closingSignal, "Close entry")
	select {
	case err := <-closed:
		t.Fatalf("closed during callback: %v", err)
	case <-time.After(20 * time.Millisecond): // negative assertion only after Close entered
	}
	releaseCallback()
	if err := waitOwnedRootError(t, done, "callback completion"); err != nil {
		t.Fatal(err)
	}
	if err := waitOwnedRootError(t, closed, "Close completion"); err != nil {
		t.Fatal(err)
	}
	if err := j.WithOwnedRoot(context.Background(), func(*os.Root) error { t.Fatal("called"); return nil }); !errors.Is(err, ErrRunJournalClosed) {
		t.Fatalf("after close: %v", err)
	}
}

func TestFileRunJournalOwnedRootPanicClosesBeforeLeaseRelease(t *testing.T) {
	j, root := ownedJournal(t)
	closeStarted, releaseClose := make(chan struct{}), make(chan struct{})
	releaseRootClose := sync.OnceFunc(func() { close(releaseClose) })
	defer releaseRootClose()
	j.closeOwnedRoot = func(r *os.Root) error {
		close(closeStarted)
		<-releaseClose
		return r.Close()
	}
	panicValue := &struct{ reason string }{"callback panic"}
	var borrowed *os.Root
	panicked := make(chan any, 1)
	go func() {
		defer func() { panicked <- recover() }()
		_ = j.WithOwnedRoot(context.Background(), func(r *os.Root) error {
			borrowed = r
			panic(panicValue)
		})
	}()
	waitOwnedRootSignal(t, closeStarted, "borrowed root close start")
	closed := make(chan error, 1)
	go func() { closed <- j.Close() }()
	waitOwnedRootSignal(t, j.closingSignal, "Close entry")
	select {
	case err := <-closed:
		t.Fatalf("lease released before borrowed root close: %v", err)
	case <-time.After(20 * time.Millisecond): // Close entered; root close is still blocked
	}
	releaseRootClose()
	select {
	case got := <-panicked:
		if got != panicValue {
			t.Fatalf("panic changed: got=%v want=%v", got, panicValue)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for callback panic")
	}
	if _, err := borrowed.Stat("."); err == nil {
		t.Fatal("borrowed root survived panic")
	}
	if err := waitOwnedRootError(t, closed, "Close completion"); err != nil {
		t.Fatal(err)
	}
	next, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatalf("writer lease not reacquirable: %v", err)
	}
	nextClosed := make(chan error, 1)
	go func() { nextClosed <- next.Close() }()
	if err := waitOwnedRootError(t, nextClosed, "reacquired journal cleanup"); err != nil {
		t.Fatal(err)
	}
}

func TestNewFileRunJournalRootCaptureRejectsPostSyncSwapAndReleasesOriginalLease(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	old := root + "-old"
	lockReleases := 0
	j, err := newFileRunJournal(root, fileRunJournalConstructorOptions{
		afterSync: func() error {
			if err := os.Rename(root, old); err != nil {
				return err
			}
			return os.Mkdir(root, 0700)
		},
		closeLock: func(lock *filelock.Lock) error {
			lockReleases++
			return lock.Close()
		},
	})
	if lockReleases != 1 {
		t.Fatalf("original lock released %d times", lockReleases)
	}
	if j != nil || !errors.Is(err, errOwnedJournalRoot) {
		t.Fatalf("post-sync swap: j=%v err=%v", j, err)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(old, root); err != nil {
		t.Fatal(err)
	}
	next, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatalf("original lease not released: %v", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewFileRunJournalRootCaptureJoinsCleanupFailures(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	candidateFailure, lockFailure := errors.New("candidate close"), errors.New("lock release")
	j, err := newFileRunJournal(root, fileRunJournalConstructorOptions{
		closeCandidate: func(r *os.Root) error { return errors.Join(r.Close(), candidateFailure) },
		closeLock:      func(l *filelock.Lock) error { return errors.Join(l.Close(), lockFailure) },
	})
	if j != nil || !errors.Is(err, candidateFailure) || !errors.Is(err, lockFailure) {
		t.Fatalf("cleanup: j=%v err=%v", j, err)
	}
	next, err := NewFileRunJournal(root)
	if err != nil {
		t.Fatalf("real lock not released: %v", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFileRunJournalOwnedRootJoinsCallbackPostcheckAndClose(t *testing.T) {
	j, root := ownedJournal(t)
	callbackFailure, closeFailure := errors.New("callback"), errors.New("root close")
	closed := false
	j.closeOwnedRoot = func(r *os.Root) error { closed = true; return errors.Join(r.Close(), closeFailure) }
	err := j.WithOwnedRoot(context.Background(), func(*os.Root) error {
		if err := os.Chmod(root, 0755); err != nil {
			return err
		}
		return callbackFailure
	})
	if !closed || !errors.Is(err, callbackFailure) || !errors.Is(err, errOwnedJournalRoot) || !errors.Is(err, closeFailure) {
		t.Fatalf("postcheck and close: closed=%v err=%v", closed, err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	j.closeOwnedRoot = nil
	if err := j.WithOwnedRoot(context.Background(), func(*os.Root) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestFileRunJournalOwnedRootPostUseSymlinkAncestor(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	j, err := NewFileRunJournal(filepath.Join(parent, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	original := parent + "-original"
	err = j.WithOwnedRoot(context.Background(), func(*os.Root) error {
		if err := os.Rename(parent, original); err != nil {
			return err
		}
		return os.Symlink(original, parent)
	})
	if !errors.Is(err, fileauthority.ErrUntrustedPath) {
		t.Fatalf("post-use symlink: %v", err)
	}
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, parent); err != nil {
		t.Fatal(err)
	}
}

func TestFileRunJournalOwnedRootPreUseCloseFailure(t *testing.T) {
	j, root := ownedJournal(t)
	closeFailure := errors.New("root close")
	j.closeOwnedRoot = func(r *os.Root) error { return errors.Join(r.Close(), closeFailure) }
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	invoked := false
	err := j.WithOwnedRoot(context.Background(), func(*os.Root) error { invoked = true; return nil })
	if invoked || !errors.Is(err, errOwnedJournalRoot) || !errors.Is(err, closeFailure) {
		t.Fatalf("precheck cleanup: invoked=%v err=%v", invoked, err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	j.closeOwnedRoot = nil
}
