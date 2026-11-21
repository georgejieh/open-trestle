package artifact

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

func pendingOwnedFixture(t *testing.T) (*PendingFileStore, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "artifacts")
	pending, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pending.Close() })
	return pending, root
}

func TestPendingFileStoreOwnedRootFreshMissingAndInvalid(t *testing.T) {
	pending, root := pendingOwnedFixture(t)
	var nilPending *PendingFileStore
	if err := nilPending.WithOwnedRoot(func(*os.Root) error { t.Fatal("nil callback invoked"); return nil }); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("nil pending: %v", err)
	}
	if err := (&PendingFileStore{}).WithOwnedRoot(func(*os.Root) error { t.Fatal("empty callback invoked"); return nil }); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("empty pending: %v", err)
	}
	if err := pending.WithOwnedRoot(nil); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("nil callback: %v", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.WithOwnedRoot(func(opened *os.Root) error {
		got, err := opened.Stat(".")
		if err != nil || !os.SameFile(info, got) {
			t.Fatalf("opened=(%v,%v)", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pending.WithOwnedRoot(func(*os.Root) error { t.Fatal("detached callback invoked"); return nil }); !errors.Is(err, ErrStoreClosed) {
		t.Fatalf("detached: %v", err)
	}
}

func TestPendingFileStoreOwnedRootReplacementAndMode(t *testing.T) {
	pending, root := pendingOwnedFixture(t)
	original := root + "-old"
	if err := os.Rename(root, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := pending.WithOwnedRoot(func(*os.Root) error { called = true; return nil }); !errors.Is(err, ErrInvalidStoreRoot) || called {
		t.Fatalf("replacement=(%v,%t)", err, called)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, root); err != nil {
		t.Fatal(err)
	}
	if err := pending.WithOwnedRoot(func(*os.Root) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := pending.WithOwnedRoot(func(*os.Root) error { called = true; return nil }); !errors.Is(err, ErrInvalidStoreRoot) || called {
		t.Fatalf("mode=(%v,%t)", err, called)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := pending.WithOwnedRoot(func(*os.Root) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestPendingFileStoreOwnedRootSymlinkParentAndRetainedPin(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "artifacts")
	pending, err := OpenPendingFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	oldParent := parent + "-old"
	if err := os.Rename(parent, oldParent); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(oldParent, parent); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := pending.WithOwnedRoot(func(*os.Root) error { called = true; return nil }); !errors.Is(err, ErrInvalidStoreRoot) || called {
		t.Fatalf("symlink before=(%v,%t)", err, called)
	}
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(oldParent, parent); err != nil {
		t.Fatal(err)
	}
	if err := pending.WithOwnedRoot(func(opened *os.Root) error {
		if err := os.Rename(parent, oldParent); err != nil {
			return err
		}
		return os.Symlink(oldParent, parent)
	}); !errors.Is(err, ErrInvalidStoreRoot) {
		t.Fatalf("symlink after: %v", err)
	}
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(oldParent, parent); err != nil {
		t.Fatal(err)
	}
	if err := pending.WithOwnedRoot(func(opened *os.Root) error {
		if err := os.Rename(parent, oldParent); err != nil {
			return err
		}
		if err := os.Mkdir(parent, 0700); err != nil {
			return err
		}
		return os.Rename(filepath.Join(oldParent, "artifacts"), root)
	}); !errors.Is(err, ErrInvalidStoreRoot) {
		t.Fatalf("retained parent pin: %v", err)
	}
	if err := pending.WithOwnedRoot(func(*os.Root) error { return nil }); err != nil {
		t.Fatalf("new pin control: %v", err)
	}
}

func TestPendingFileStoreOwnedRootCallbackErrorAndPanicClose(t *testing.T) {
	pending, _ := pendingOwnedFixture(t)
	sentinel := errors.New("callback sentinel")
	if err := pending.WithOwnedRoot(func(*os.Root) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("callback error: %v", err)
	}
	var borrowed *os.Root
	func() {
		defer func() {
			if got := recover(); got != sentinel {
				t.Fatalf("panic=%v", got)
			}
		}()
		_ = pending.WithOwnedRoot(func(root *os.Root) error { borrowed = root; panic(sentinel) })
	}()
	if _, err := borrowed.Stat("."); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("borrowed root not closed: %v", err)
	}
	if err := pending.WithOwnedRoot(func(*os.Root) error { return nil }); err != nil {
		t.Fatalf("mutex not released: %v", err)
	}
}

func TestPendingFileStoreOwnedRootPanicStillPostchecksAndCloses(t *testing.T) {
	pending, path := pendingOwnedFixture(t)
	type postchecks struct{ pin, opened, leaf error }
	observed := make(chan postchecks, 1)
	pending.state.onOwnedRootPostcheck = func(pin, opened, leaf error) {
		observed <- postchecks{pin, opened, leaf}
	}
	sentinel := errors.New("original callback panic")
	var borrowed *os.Root
	func() {
		defer func() {
			if got := recover(); got != sentinel {
				t.Fatalf("panic=%v, want original sentinel", got)
			}
		}()
		_ = pending.WithOwnedRoot(func(root *os.Root) error {
			borrowed = root
			if err := os.Chmod(path, 0755); err != nil {
				t.Fatal(err)
			}
			if err := root.Close(); err != nil { // Force cleanup Close failure.
				t.Fatal(err)
			}
			panic(sentinel)
		})
	}()
	select {
	case checks := <-observed:
		if !errors.Is(checks.pin, fileauthority.ErrUntrustedPath) ||
			!errors.Is(checks.opened, os.ErrClosed) ||
			!errors.Is(checks.leaf, ErrInvalidStoreRoot) {
			t.Fatalf("postchecks did not inspect retained pin, opened root, and leaf: %+v", checks)
		}
	default:
		t.Fatal("postchecks did not run after callback panic")
	}
	if _, err := borrowed.Stat("."); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("borrowed root not closed: %v", err)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	pending.state.onOwnedRootPostcheck = nil
	if err := pending.WithOwnedRoot(func(*os.Root) error { return nil }); err != nil {
		t.Fatalf("pending lease not usable after panic: %v", err)
	}
}

func TestPendingFileStoreOwnedRootPostcheckPanicStillCloses(t *testing.T) {
	pending, _ := pendingOwnedFixture(t)
	sentinel := errors.New("postcheck observer panic")
	var borrowed *os.Root
	pending.state.onOwnedRootPostcheck = func(error, error, error) { panic(sentinel) }
	func() {
		defer func() {
			if got := recover(); got != sentinel {
				t.Fatalf("panic=%v, want observer sentinel", got)
			}
		}()
		_ = pending.WithOwnedRoot(func(root *os.Root) error { borrowed = root; return nil })
	}()
	if _, err := borrowed.Stat("."); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("borrowed root not closed after postcheck panic: %v", err)
	}
	pending.state.onOwnedRootPostcheck = nil
	if err := pending.WithOwnedRoot(func(*os.Root) error { return nil }); err != nil {
		t.Fatalf("pending lease not usable after postcheck panic: %v", err)
	}
}

func TestPendingFileStoreOwnedRootCloseAndActivateBlocked(t *testing.T) {
	for _, operation := range []string{"close", "activate"} {
		t.Run(operation, func(t *testing.T) {
			pending, _ := pendingOwnedFixture(t)
			// A witness is sent only after TryLock fails while the callback holds state.mu.
			// The contender can still be descheduled after sending it.
			contended := make(chan struct{}, 1)
			pending.state.onLeaseMethodContended = func() { contended <- struct{}{} }
			entered, release := make(chan struct{}), make(chan struct{})
			released := false
			defer func() {
				if !released {
					close(release)
				}
			}()
			scoped := make(chan error, 1)
			go func() {
				scoped <- pending.WithOwnedRoot(func(*os.Root) error { close(entered); <-release; return nil })
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("callback did not enter")
			}
			finished := make(chan error, 1)
			go func() {
				if operation == "close" {
					finished <- pending.Close()
				} else {
					store, err := pending.Activate()
					if store != nil {
						_ = store.Close()
					}
					finished <- err
				}
			}()
			select {
			case <-contended:
			case <-time.After(3 * time.Second):
				t.Fatal("method did not fail TryLock while callback held the mutex")
			}
			// The failed TryLock proves actual contention, not that the following
			// Lock has run yet. The scheduler may pause after the witness.
			select {
			case err := <-finished:
				t.Fatalf("%s returned during callback: %v", operation, err)
			case <-time.After(75 * time.Millisecond):
			}
			close(release)
			released = true
			select {
			case err := <-scoped:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("scoped operation blocked")
			}
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("close/activate blocked")
			}
			pending.state.onLeaseMethodContended = nil // Both goroutines have finished.
			if err := pending.WithOwnedRoot(func(*os.Root) error { t.Fatal("callback after detach"); return nil }); !errors.Is(err, ErrStoreClosed) {
				t.Fatalf("detached: %v", err)
			}
		})
	}
}

func TestPendingFileStoreOwnedRootJoinsCallbackPostcheckAndClose(t *testing.T) {
	pending, path := pendingOwnedFixture(t)
	sentinel := errors.New("callback failed")
	err := pending.WithOwnedRoot(func(root *os.Root) error {
		if err := os.Chmod(path, 0755); err != nil {
			return err
		}
		if err := root.Close(); err != nil {
			return err
		} // Force a cleanup error without an injection seam.
		return sentinel
	})
	if !errors.Is(err, sentinel) || !errors.Is(err, ErrInvalidStoreRoot) || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("joined errors: %v", err)
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := pending.WithOwnedRoot(func(*os.Root) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
