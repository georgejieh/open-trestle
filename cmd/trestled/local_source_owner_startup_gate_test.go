package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalSourceOwnerGateRecordedRestartKeepsLeafAndRefusesMissingRecord(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	args := ownerStartupGitFlags(t, state)
	getenv := daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"})
	first, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(state, localSourceOwnerLeaf)
	original, err := os.ReadFile(leaf)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(leaf)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("recorded same-inode restart: %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(leaf)
	if err != nil {
		t.Fatal(err)
	}
	bytesAfter, err := os.ReadFile(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !bytes.Equal(original, bytesAfter) {
		t.Fatal("recorded restart rewrote owner")
	}
	if err := os.Remove(leaf); err != nil {
		t.Fatal(err)
	}
	rejected, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if rejected != nil {
		rejected.Close()
		t.Fatal("recordless runtime enrolled")
	}
	if err == nil {
		t.Fatal("recordless runtime accepted")
	}
	if _, statErr := os.Lstat(leaf); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("recordless restart minted owner: %v", statErr)
	}
	ownerStartupAssertLeaseReacquisition(t, state)
}

func TestLocalNoGitNestedMissingSuffixKeepsOriginalParent(t *testing.T) {
	root := t.TempDir()
	original, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "new", "deep", "state")
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", state, "--tenant", "tenant-a", "--repository", "repo-a"}
	getenv := daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"})
	built, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("trusted 0755 original parent with nested missing suffix: %v", err)
	}
	if err := built.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := os.Lstat(root)
	if err != nil || !os.SameFile(original, current) || original.Mode() != current.Mode() {
		t.Fatalf("original parent changed: %v %v", original, current)
	}
	for _, path := range []string{filepath.Join(root, "new"), filepath.Join(root, "new", "deep"), state, filepath.Join(state, "artifacts")} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode() != os.ModeDir|0700 {
			t.Fatalf("constructed private suffix %q: %v %v", path, info, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(state, localSourceOwnerLeaf)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no-Git minted owner: %v", err)
	}
	ownerStartupAssertLeaseReacquisition(t, state)
}

type startupCancellationCycle struct{}

func (*startupCancellationCycle) Error() string   { return "cycle" }
func (e *startupCancellationCycle) Unwrap() error { return e }

type startupCancellationEmpty struct{}

func (startupCancellationEmpty) Error() string   { return "empty" }
func (startupCancellationEmpty) Unwrap() []error { return nil }

func TestOnlyDaemonStartupCancellationRequiresEveryBoundedLeaf(t *testing.T) {
	cleanup := errors.New("cleanup failed")
	cases := []struct {
		name     string
		err      error
		canceled error
		want     bool
	}{
		{"pure", context.Canceled, context.Canceled, true},
		{"wrapped", fmt.Errorf("during build: %w", context.Canceled), context.Canceled, true},
		{"joined-canceled", errors.Join(context.Canceled, fmt.Errorf("wrapped: %w", context.Canceled)), context.Canceled, true},
		{"cleanup-joined", errors.Join(context.Canceled, cleanup), context.Canceled, false},
		{"non-context", cleanup, context.Canceled, false},
		{"wrong-context", context.DeadlineExceeded, context.Canceled, false},
		{"empty", startupCancellationEmpty{}, context.Canceled, false},
		{"cycle", &startupCancellationCycle{}, context.Canceled, false},
		{"nil-context", context.Canceled, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := onlyDaemonStartupCancellation(tc.err, tc.canceled); got != tc.want {
				t.Fatalf("classifier=%t want=%t error=%v", got, tc.want, tc.err)
			}
			if tc.name == "cleanup-joined" && (!errors.Is(tc.err, cleanup) || !errors.Is(tc.err, context.Canceled)) {
				t.Fatal("join lost primary or cleanup sentinel")
			}
		})
	}
	deep := error(context.Canceled)
	for i := 0; i < 65; i++ {
		deep = fmt.Errorf("wrapper: %w", deep)
	}
	if onlyDaemonStartupCancellation(deep, context.Canceled) {
		t.Fatal("unbounded wrapper depth accepted")
	}
}
