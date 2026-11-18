//go:build linux

package secretscan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestScanHelperSessionHoldsNoInheritedDescriptor opens a file, a pipe and a
// socket in this process without close-on-exec, as descriptors this process
// inherited would be, so that the spawn passes them on, and checks after a
// scan that the real helper holds none of them.
func TestScanHelperSessionHoldsNoInheritedDescriptor(t *testing.T) {
	config := scanHelperForTest(t)
	file, err := syscall.Open(config.HelperPath, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var pipe [2]int
	if err := syscall.Pipe(pipe[:]); err != nil {
		t.Fatal(err)
	}
	socket, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	inherited := []int{file, pipe[0], pipe[1], socket}
	defer func() {
		for _, descriptor := range inherited {
			_ = syscall.Close(descriptor)
		}
	}()
	targets := map[string]bool{}
	for _, descriptor := range inherited {
		target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", descriptor))
		if err != nil {
			t.Fatal(err)
		}
		targets[target] = true
	}
	session := openHelperSessionForTest(t, config)
	if result, err := session.Scan(context.Background(), [][]byte{[]byte("ordinary text")}); err != nil || !result.Complete() {
		t.Fatalf("scan: %v", err)
	}
	pid := session.helperPID()
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name())); err == nil && targets[target] {
			t.Fatalf("helper holds inherited descriptor %s (%s)", entry.Name(), target)
		}
	}
	if err := session.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestScanHelperGroupWritableCacheIsRefused(t *testing.T) {
	config := scanHelperForTest(t)
	config.CacheDirectory = filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(config.CacheDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config.CacheDirectory, 0o770); err != nil {
		t.Fatal(err)
	}
	if session, err := OpenSession(context.Background(), config); session != nil || !errors.Is(err, ErrCacheUntrusted) {
		t.Fatalf("session with a group-writable cache was not refused: %v", err)
	}
	if err := Prewarm(context.Background(), config); !errors.Is(err, ErrCacheUntrusted) {
		t.Fatalf("prewarm with a group-writable cache was not refused: %v", err)
	}
}
