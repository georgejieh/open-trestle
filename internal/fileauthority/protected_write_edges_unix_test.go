//go:build unix

package fileauthority

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

func edgeProtectedWriteDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestWriteNewProtectedFileConcurrentExclusiveCreateHasSingleWinner(t *testing.T) {
	dir := edgeProtectedWriteDir(t)
	path := filepath.Join(dir, "retained-memory-input.json")
	const workers = 12
	type result struct {
		index   int
		content []byte
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, workers)
	var ready sync.WaitGroup
	ready.Add(workers)
	for i := 0; i < workers; i++ {
		content := []byte{byte('A' + i), '\n'}
		go func(index int, content []byte) {
			ready.Done()
			<-start
			results <- result{index: index, content: content, err: WriteNewProtectedFile(context.Background(), path, content, len(content))}
		}(i, content)
	}
	ready.Wait()
	close(start)
	var winner result
	successes := 0
	refusals := 0
	var unexpected []result
	for i := 0; i < workers; i++ {
		got := <-results
		switch {
		case got.err == nil:
			successes++
			winner = got
		case errors.Is(got.err, ErrProtectedWriteRefused):
			refusals++
		default:
			unexpected = append(unexpected, got)
		}
	}
	if len(unexpected) != 0 {
		t.Fatalf("concurrent protected write failures after joining all writers: %v", unexpected)
	}
	if successes != 1 || refusals != workers-1 {
		t.Fatalf("exclusive create successes=%d refusals=%d workers=%d", successes, refusals, workers)
	}
	final, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(final, winner.content) {
		t.Fatalf("final bytes %q do not match winner %d content %q", final, winner.index, winner.content)
	}
	if err := WriteNewProtectedFile(context.Background(), path, []byte("overwrite"), 64); !errors.Is(err, ErrProtectedWriteRefused) {
		t.Fatalf("post-race overwrite did not fail closed: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, winner.content) {
		t.Fatal("post-race overwrite refusal changed winner bytes")
	}
}

func TestWriteNewProtectedFileRestrictiveUmaskLeavesOwnedEmptyIncomplete(t *testing.T) {
	dir := edgeProtectedWriteDir(t)
	path := filepath.Join(dir, "retained-memory-input.json")
	oldUmask := syscall.Umask(0o777)
	restored := false
	defer func() {
		if !restored {
			syscall.Umask(oldUmask)
		}
	}()
	err := WriteNewProtectedFile(context.Background(), path, []byte("secret"), 6)
	syscall.Umask(oldUmask)
	restored = true
	if !errors.Is(err, ErrProtectedWriteIncomplete) || errors.Is(err, ErrProtectedWriteRefused) {
		t.Fatalf("restrictive umask error=%v, want incomplete after create", err)
	}
	info, statErr := os.Lstat(path)
	if statErr != nil {
		t.Fatalf("restrictive umask did not leave residual file: %v", statErr)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != 0 || !TrustedOwner(info) {
		t.Fatalf("residual file authority drift: mode=%v size=%d trusted_owner=%v", info.Mode(), info.Size(), TrustedOwner(info))
	}
	if info.Mode().Perm() == 0o600 {
		t.Fatalf("restrictive umask unexpectedly preserved trusted 0600 mode: %v", info.Mode())
	}
}
