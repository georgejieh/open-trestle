package scm

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestWalkTreeVisitsEntriesInTreeOrderWithoutBlobs(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	algorithm := evidence.RevisionAlgorithmSHA1
	blob := writeLooseObject(t, directory, algorithm, "blob", []byte("x"))
	missingBlob := fmt.Sprintf("%040d", 3)
	child := writeLooseObject(t, directory, algorithm, "tree", append(localTreeEntry(t, algorithm, evidence.GitTreeModeRegular, []byte("a.go"), blob), localTreeEntry(t, algorithm, evidence.GitTreeModeSymlink, []byte("link"), blob)...))
	root := append(localTreeEntry(t, algorithm, evidence.GitTreeModeDirectory, []byte("d"), child), localTreeEntry(t, algorithm, evidence.GitTreeModeDirectory, []byte("e"), child)...)
	root = append(root, localTreeEntry(t, algorithm, evidence.GitTreeModeRegular, []byte("f\xff"), blob)...)
	root = append(root, localTreeEntry(t, algorithm, evidence.GitTreeModeGitlink, []byte("sub"), fmt.Sprintf("%040d", 1))...)
	root = append(root, localTreeEntry(t, algorithm, evidence.GitTreeModeRegular, []byte("z"), missingBlob)...)
	revision := writeLocalRevision(t, directory, algorithm, root)

	var got []string
	walk, err := store.WalkTree(context.Background(), revision, 100, func(e LocalGitTreeEntry) error {
		got = append(got, string(e.Mode)+" "+e.Path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"100644 d/a.go", "120000 d/link", "100644 e/a.go", "120000 e/link", "160000 sub", "100644 z"}
	if fmt.Sprint(got) != fmt.Sprint(want) || walk.Entries != len(want) || walk.Truncated || walk.InvalidPaths != 1 {
		t.Fatalf("walk = %v %+v", got, walk)
	}

	got = nil
	walk, err = store.WalkTree(context.Background(), revision, 3, func(e LocalGitTreeEntry) error {
		got = append(got, e.Path)
		return nil
	})
	if err != nil || !walk.Truncated || walk.Entries != 3 || len(got) != 3 {
		t.Fatalf("limited walk = %v %+v %v", got, walk, err)
	}

	stop := errors.New("stop")
	if _, err := store.WalkTree(context.Background(), revision, 100, func(LocalGitTreeEntry) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("visitor error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.WalkTree(ctx, revision, 100, func(LocalGitTreeEntry) error { return nil }); err == nil {
		t.Fatal("canceled walk succeeded")
	}
}

func TestWalkTreeRejectsMissingTrees(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	algorithm := evidence.RevisionAlgorithmSHA1
	root := localTreeEntry(t, algorithm, evidence.GitTreeModeDirectory, []byte("d"), fmt.Sprintf("%040d", 4))
	revision := writeLocalRevision(t, directory, algorithm, root)
	if _, err := store.WalkTree(context.Background(), revision, 100, func(LocalGitTreeEntry) error { return nil }); !errors.Is(err, LocalGitRevisionObjectUnavailable) {
		t.Fatalf("missing subtree = %v", err)
	}
}
