package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/setup"
)

// The historical writer creates a real, replayable canceled v3 journal in an
// old scope. This is runtime history, not an unknown direct-root sibling.
func ownerStartupLegacyState(t *testing.T) string {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	historicalPacketJournal(t, state, true)
	journal, err := controlplane.NewFileRunJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	inventory, inspectErr := journal.InspectStartupInventory(context.Background())
	closeErr := journal.Close()
	if inspectErr != nil || closeErr != nil || inventory.Plans != 1 || inventory.Streams != 1 || inventory.Events < 2 {
		t.Fatalf("legacy journal fixture: inventory=%+v inspect=%v close=%v", inventory, inspectErr, closeErr)
	}
	return state
}

func ownerStartupGitFlags(t *testing.T, state string) []string {
	t.Helper()
	root := filepath.Dir(state)
	objects := filepath.Join(root, "repository", ".git", "objects")
	if err := os.MkdirAll(objects, 0o700); err != nil {
		t.Fatal(err)
	}
	daemonTestRevision(t, objects, []byte("package main\nfunc main() {}\n"))
	setupPath := filepath.Join(root, "setup", "plan.json")
	plan, err := setup.NewPlan(setup.ProfileLocalSingleNode, "tenant-a", "repo-a", "platform-owner", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	writeSnapshotSetup(t, setupPath, plan)
	return []string{"--listen", "127.0.0.1:0", "--state-dir", state,
		"--tenant", "tenant-a", "--repository", "repo-a",
		"--setup-state", setupPath, "--expected-setup-root-identity", plan.RootIdentity(),
		"--local-git-objects-root", objects, "--local-git-repository-authority", "local.test",
		"--local-git-repository-namespace", "team", "--local-git-repository-name", "repository"}
}

func ownerStartupJournalBytes(t *testing.T, state string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(state)
	if err != nil {
		t.Fatal(err)
	}
	saved := make(map[string][]byte)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".run-plan.json") && !strings.HasSuffix(entry.Name(), ".run.jsonl") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(state, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		saved[entry.Name()] = data
	}
	if len(saved) != 2 {
		t.Fatalf("legacy fixture lacks plan and stream: %d", len(saved))
	}
	return saved
}

func ownerStartupAssertLeaseReacquisition(t *testing.T, state string) {
	t.Helper()
	pending, err := artifact.OpenPendingFileStore(filepath.Join(state, "artifacts"))
	if err != nil {
		t.Fatalf("artifact lease not reacquirable: %v", err)
	}
	if err := pending.Close(); err != nil {
		t.Fatalf("reacquired artifact close: %v", err)
	}
	journal, err := controlplane.NewFileRunJournal(state)
	if err != nil {
		t.Fatalf("journal lease not reacquirable: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("reacquired journal close: %v", err)
	}
}

func TestBuildDaemonRecordlessLegacyRuntimeCannotEnrollLocalGit(t *testing.T) {
	state := ownerStartupLegacyState(t)
	args := ownerStartupGitFlags(t, state)
	before := ownerStartupJournalBytes(t, state)
	getenv := daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"})
	built, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if built != nil {
		if closeErr := built.Close(); closeErr != nil {
			t.Fatalf("unexpectedly built daemon close: %v", closeErr)
		}
	}
	owner := filepath.Join(state, localSourceOwnerLeaf)
	ownerInfo, ownerErr := os.Lstat(owner)
	if ownerInfo != nil || !errors.Is(ownerErr, os.ErrNotExist) {
		t.Fatalf("recordless runtime published an owner: info=%v err=%v", ownerInfo, ownerErr)
	}
	if after := ownerStartupJournalBytes(t, state); !reflect.DeepEqual(before, after) {
		t.Fatal("rejected startup changed legacy plan or event stream")
	}
	ownerStartupAssertLeaseReacquisition(t, state)
	if built != nil || err == nil {
		t.Fatalf("recordless nonempty LOCAL Git runtime accepted: daemon=%v error=%v", built != nil, err)
	}
	for _, name := range []string{"audit", "diagnostics"} {
		if _, statErr := os.Lstat(filepath.Join(state, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("rejected startup created %s: %v", name, statErr)
		}
	}
}

func TestBuildDaemonNoGitAcceptsLegacyTerminalV3WithoutOwner(t *testing.T) {
	state := ownerStartupLegacyState(t)
	before := ownerStartupJournalBytes(t, state)
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", state,
		"--tenant", "tenant-a", "--repository", "repo-a"}
	getenv := daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"})
	built, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if err != nil || built == nil {
		t.Fatalf("no-Git legacy v3 startup: daemon=%v err=%v", built, err)
	}
	if err := built.Close(); err != nil {
		t.Fatal(err)
	}
	if after := ownerStartupJournalBytes(t, state); !reflect.DeepEqual(before, after) {
		t.Fatal("no-Git startup changed terminal v3 history")
	}
	if _, err := os.Lstat(filepath.Join(state, localSourceOwnerLeaf)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("no-Git startup published an owner: %v", err)
	}
	journal, err := controlplane.NewFileRunJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	inventory, inspectErr := journal.InspectStartupInventory(context.Background())
	closeErr := journal.Close()
	if inspectErr != nil || closeErr != nil || inventory.Plans != 1 || inventory.Streams != 1 || inventory.Events < 2 {
		t.Fatalf("post-startup exhaustive v3 inventory: %+v inspect=%v close=%v", inventory, inspectErr, closeErr)
	}
	ownerStartupAssertLeaseReacquisition(t, state)
}
