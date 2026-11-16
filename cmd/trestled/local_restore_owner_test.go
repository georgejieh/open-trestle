package main

import (
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"os"
	"path/filepath"
	"testing"
)

func TestRestoredOwnerChecksSameDirectoriesAndSetup(t *testing.T) {
	state, setupPath, plan := snapshotFixture(t)
	writeSnapshotSetup(t, setupPath, plan)
	artifactPath := filepath.Join(state, "artifacts")
	if err := os.Mkdir(artifactPath, 0o700); err != nil {
		t.Fatal(err)
	}
	gitPath := filepath.Join(t.TempDir(), "objects")
	if err := os.Mkdir(gitPath, 0o700); err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("local.test", []string{"team"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	stateRoot, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	defer stateRoot.Close()
	artifactRoot, err := os.OpenRoot(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	defer artifactRoot.Close()
	gitRoot, sourceDigest, err := openDaemonLocalGitRoot(gitPath, repository)
	if err != nil {
		t.Fatal(err)
	}
	defer gitRoot.Close()
	stateID, err := observeLocalSourceDirectory(state, stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	artifactID, err := observeLocalSourceArtifactDirectory(stateRoot, artifactRoot, state)
	if err != nil {
		t.Fatal(err)
	}
	gitID, err := observeLocalSourceDirectory(gitPath, gitRoot)
	if err != nil {
		t.Fatal(err)
	}
	store, err := scm.NewLocalGitObjectStore(gitRoot, repository)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := scm.NewLocalGitSourceAdapter(store)
	if err != nil {
		t.Fatal(err)
	}
	record := localSourceOwnerRecord{StatePath: state, ArtifactPath: artifactPath, GitObjectsPath: gitPath, TenantID: plan.TenantID(), RepositoryID: plan.RepositoryID(), RepositoryIdentity: repository.Identity(), AdapterIdentity: adapter.Identity().Identity(), Profile: string(store.Profile()), SourcePathDigest: sourceDigest, State: stateID, Artifact: artifactID, Git: gitID}
	body, err := encodeLocalSourceOwnerRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, localSourceOwnerLeaf), body, 0o600); err != nil {
		t.Fatal(err)
	}
	observed, observedPlan, err := inspectRestoredOwner(context.Background(), state, setupPath, stateRoot, artifactRoot, repository)
	if err != nil || observed != record || observedPlan.Identity() != plan.Identity() {
		t.Fatalf("owner observation: %v", err)
	}
	assertSnapshotNoWrite(t, filepath.Dir(state), func() {
		_, _, err = inspectRestoredOwner(context.Background(), state, setupPath, stateRoot, artifactRoot, repository)
		if err != nil {
			t.Fatal(err)
		}
	})
	if err := os.Rename(gitPath, gitPath+".retained"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(gitPath, 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err = inspectRestoredOwner(context.Background(), state, setupPath, stateRoot, artifactRoot, repository)
	if !errors.Is(err, ErrLocalSourceOwnerMismatch) {
		t.Fatalf("recreated Git root accepted: %v", err)
	}
}
