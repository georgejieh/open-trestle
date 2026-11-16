package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/setup"
)

func TestBuildDaemonLocalOwnerGateFreshGit(t *testing.T) {
	root := t.TempDir()
	// The saved missing-state boundary requires an original private parent.
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	objects := filepath.Join(root, "repository", ".git", "objects")
	if err := os.MkdirAll(objects, 0o700); err != nil {
		t.Fatal(err)
	}
	daemonTestRevision(t, objects, []byte("package main\nfunc main() {}\n"))

	setupDirectory := filepath.Join(root, "setup")
	if err := os.Mkdir(setupDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	setupPath := filepath.Join(setupDirectory, "plan.json")
	plan, err := setup.NewPlan(setup.ProfileLocalSingleNode, "tenant-a", "repo-a", "platform-owner", time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	setupFile, err := setup.OpenStateFile(setupPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := setupFile.Initialize(context.Background(), plan); err != nil {
		_ = setupFile.Close()
		t.Fatal(err)
	}
	if err := setupFile.Close(); err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(root, "runtime")
	artifactPath := filepath.Join(statePath, "artifacts")
	if _, err := os.Lstat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first-use state must be missing before build: %v", err)
	}
	args := []string{"--listen", "127.0.0.1:0", "--state-dir", statePath, "--tenant", "tenant-a", "--repository", "repo-a", "--setup-state", setupPath, "--expected-setup-root-identity", plan.RootIdentity(), "--local-git-objects-root", objects, "--local-git-repository-authority", "local.test", "--local-git-repository-namespace", "team", "--local-git-repository-name", "repository"}
	getenv := func(key string) string {
		if key == "OPEN_TRESTLE_API_TOKEN" {
			return "01234567890123456789012345678901"
		}
		return ""
	}
	daemon, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("valid fresh LOCAL Git daemon must build before owner assertion: %v", err)
	}
	t.Cleanup(func() {
		if err := daemon.Close(); err != nil {
			t.Errorf("daemon close: %v", err)
		}
		pending, err := artifact.OpenPendingFileStore(artifactPath)
		if err != nil {
			t.Errorf("artifact lease not reacquirable after close: %v", err)
		} else if err := pending.Close(); err != nil {
			t.Errorf("reacquired artifact lease close: %v", err)
		}
		journal, err := controlplane.NewFileRunJournal(statePath)
		if err != nil {
			t.Errorf("journal lease not reacquirable after close: %v", err)
		} else if err := journal.Close(); err != nil {
			t.Errorf("reacquired journal lease close: %v", err)
		}
	})

	openRoot := func(path string) *os.Root {
		t.Helper()
		opened, err := os.OpenRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := opened.Close(); err != nil {
				t.Errorf("close independent root %q: %v", path, err)
			}
		})
		return opened
	}
	gitRoot := openRoot(objects)
	stateRoot := openRoot(statePath)
	artifactRoot := openRoot(artifactPath)
	for _, item := range []struct {
		path string
		root *os.Root
	}{{objects, gitRoot}, {statePath, stateRoot}, {artifactPath, artifactRoot}} {
		if _, err := observeLocalSourceDirectory(item.path, item.root); err != nil {
			t.Fatalf("private 0700 opened directory %q: %v", item.path, err)
		}
	}

	leaf, err := stateRoot.Lstat(localSourceOwnerLeaf)
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fresh LOCAL Git build omitted canonical %s: %v", localSourceOwnerLeaf, err)
	}
	if err != nil {
		t.Fatalf("owner leaf lookup: %v", err)
	}
	if !ownerLeafInfo(leaf) {
		t.Fatalf("owner leaf must be private regular 0600: mode=%v size=%d", leaf.Mode(), leaf.Size())
	}
	recorded, err := readLocalSourceOwnerRecord(stateRoot, statePath)
	if err != nil {
		t.Fatalf("strict rooted owner reader: %v", err)
	}
	repository, err := evidence.NewRepositoryIdentity("local.test", []string{"team"}, "repository")
	if err != nil {
		t.Fatal(err)
	}
	digestRoot, sourcePathDigest, err := openDaemonLocalGitRoot(objects, repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := digestRoot.Close(); err != nil {
		t.Fatal(err)
	}
	objectStore, err := scm.NewLocalGitObjectStore(gitRoot, repository)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := scm.NewLocalGitSourceAdapter(objectStore)
	if err != nil {
		t.Fatal(err)
	}
	gitID, err := observeLocalSourceDirectory(objects, gitRoot)
	if err != nil {
		t.Fatal(err)
	}
	stateID, err := observeLocalSourceDirectory(statePath, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	artifactID, err := observeLocalSourceArtifactDirectory(stateRoot, artifactRoot, statePath)
	if err != nil {
		t.Fatal(err)
	}
	expected := localSourceOwnerRecord{
		StatePath: statePath, ArtifactPath: artifactPath, GitObjectsPath: objects,
		TenantID: "tenant-a", RepositoryID: "repo-a", RepositoryIdentity: repository.Identity(),
		AdapterIdentity: adapter.Identity().Identity(), Profile: string(objectStore.Profile()),
		SourcePathDigest: sourcePathDigest, Git: gitID, State: stateID, Artifact: artifactID,
	}
	if err := matchLocalSourceOwnerRecord(recorded, expected); err != nil {
		t.Fatalf("owner record does not match independent opened roots and configured Git adapter: %v", err)
	}
	entries, err := os.ReadDir(statePath)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	want := []string{".run-writer.lock", localSourceOwnerLeaf, "artifacts", "audit", "diagnostics"}
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Fatalf("state root has owner temp or unknown leaf: got %q, want %q", names, want)
	}
}
