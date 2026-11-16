package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Cancel from the synchronous environment read, after runDaemon has accepted
// the live context but before the local state constructors can run.
func TestRunDaemonLocalNoGitCancellationDuringBuildIsNormal(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fixture must begin without constructed state: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tokenRead := false
	getenv := func(key string) string {
		if key == "OPEN_TRESTLE_API_TOKEN" {
			tokenRead = true
			cancel()
			return "01234567890123456789012345678901"
		}
		return ""
	}
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", state, "--tenant", "tenant-a", "--repository", "repo-a"}
	var stdout, stderr bytes.Buffer
	runErr := runDaemon(ctx, args, getenv, &stdout, &stderr)
	if !tokenRead || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("fixture did not cancel synchronously during build: tokenRead=%t context=%v", tokenRead, ctx.Err())
	}
	if runErr != nil {
		t.Errorf("normal during-build cancellation must return nil (exit status 0), got: %v", runErr)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("canceled daemon emitted listener or diagnostic output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	after, err := os.Lstat(root)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		t.Fatalf("original private root changed: before=%v after=%v err=%v", before, after, err)
	}
	if _, err := os.Lstat(state); errors.Is(err, os.ErrNotExist) {
		return // No constructor ran; there are no leases to reacquire.
	} else if err != nil {
		t.Fatalf("state inspection: %v", err)
	}
	// If a future build constructs state before noticing cancellation, it must
	// still close its file-store leases. No Git source or worker is configured.
	ownerStartupAssertLeaseReacquisition(t, state)
	t.Error("early cancellation constructed the state directory")
}
