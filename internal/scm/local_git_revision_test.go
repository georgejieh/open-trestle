package scm

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestReadLocalGitRevisionBuildsVerifiedResults(t *testing.T) {
	for _, algorithm := range []evidence.RevisionAlgorithm{evidence.RevisionAlgorithmSHA1, evidence.RevisionAlgorithmSHA256} {
		t.Run(string(algorithm), func(t *testing.T) {
			directory, store := newLocalGitObjectStoreFixture(t)
			content := []byte("content")
			blobDigest := writeLooseObject(t, directory, algorithm, "blob", content)
			rootContent := localTreeEntry(t, algorithm, evidence.GitTreeModeRegular, []byte("file.txt"), blobDigest)
			revision := writeLocalRevision(t, directory, algorithm, rootContent)
			result, err := ReadLocalGitRevision(context.Background(), store, revision)
			if err != nil {
				t.Fatalf("ReadLocalGitRevision() error = %v", err)
			}
			if result.RevisionIdentity() != revision.Identity() || result.RepositoryIdentity() != store.RepositoryIdentity() || result.FileCount() != 1 || result.TotalContentBytes() != int64(len(content)) {
				t.Fatalf("result metadata = %#v", result)
			}
			if result.GitCommitIdentity() == "" || result.GitTreeGraphIdentity() == "" || result.CorrespondenceIdentity() == "" || result.Manifest().Identity() == "" {
				t.Fatal("result evidence identities are empty")
			}
			if got := result.Contents()["file.txt"]; !bytes.Equal(got, content) {
				t.Fatalf("content = %q, want %q", got, content)
			}
		})
	}
}

func TestReadLocalGitRevisionExpandsNestedSharedObjects(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	algorithm := evidence.RevisionAlgorithmSHA1
	content := []byte("shared")
	blobDigest := writeLooseObject(t, directory, algorithm, "blob", content)
	childContent := localTreeEntry(t, algorithm, evidence.GitTreeModeExecutable, []byte("run"), blobDigest)
	childDigest := writeLooseObject(t, directory, algorithm, "tree", childContent)
	rootContent := append(localTreeEntry(t, algorithm, evidence.GitTreeModeDirectory, []byte("a"), childDigest), localTreeEntry(t, algorithm, evidence.GitTreeModeDirectory, []byte("b"), childDigest)...)
	revision := writeLocalRevision(t, directory, algorithm, rootContent)
	result, err := ReadLocalGitRevision(context.Background(), store, revision)
	if err != nil {
		t.Fatalf("ReadLocalGitRevision() error = %v", err)
	}
	contents := result.Contents()
	if result.FileCount() != 2 || result.TotalContentBytes() != int64(2*len(content)) || !bytes.Equal(contents["a/run"], content) || !bytes.Equal(contents["b/run"], content) {
		t.Fatalf("result = files %d, bytes %d, contents %#v", result.FileCount(), result.TotalContentBytes(), contents)
	}
	contents["a/run"][0] = 'X'
	if bytes.Equal(contents["a/run"], contents["b/run"]) || !bytes.Equal(result.Contents()["a/run"], content) {
		t.Fatal("result contents are not independent defensive copies")
	}
	limits := standardLocalGitRevisionLimits()
	limits.maxResultBytes = int64(len(content))
	if limited, err := readLocalGitRevision(context.Background(), store, revision, limits); !errors.Is(err, LocalGitRevisionResourceLimit) || limited.RevisionIdentity() != "" {
		t.Fatalf("limited shared content = (%#v, %v)", limited, err)
	}
}

func TestReadLocalGitRevisionSupportsEmptyTree(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	revision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, nil)
	result, err := ReadLocalGitRevision(context.Background(), store, revision)
	if err != nil || result.FileCount() != 0 || result.TotalContentBytes() != 0 || result.Contents() == nil || len(result.Contents()) != 0 || result.Manifest().Identity() == "" {
		t.Fatalf("ReadLocalGitRevision() = (%#v, %v)", result, err)
	}
}

func TestReadLocalGitRevisionRejectsUnsupportedEntries(t *testing.T) {
	for _, testCase := range []struct {
		name string
		mode evidence.GitTreeMode
		err  error
	}{
		{name: "symlink", mode: evidence.GitTreeModeSymlink, err: LocalGitRevisionUnsupportedSymlink},
		{name: "gitlink", mode: evidence.GitTreeModeGitlink, err: LocalGitRevisionUnsupportedGitlink},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			directory, store := newLocalGitObjectStoreFixture(t)
			algorithm := evidence.RevisionAlgorithmSHA1
			digest := writeLooseObject(t, directory, algorithm, "blob", []byte("target"))
			if testCase.mode == evidence.GitTreeModeGitlink {
				digest = fmt.Sprintf("%040d", 1)
			}
			rootContent := localTreeEntry(t, algorithm, testCase.mode, []byte("entry"), digest)
			revision := writeLocalRevision(t, directory, algorithm, rootContent)
			result, err := ReadLocalGitRevision(context.Background(), store, revision)
			if !errors.Is(err, testCase.err) || result.RevisionIdentity() != "" {
				t.Fatalf("ReadLocalGitRevision() = (%#v, %v)", result, err)
			}
		})
	}
}

func TestReadLocalGitRevisionClassifiesMissingAndInvalidObjects(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		directory, store := newLocalGitObjectStoreFixture(t)
		algorithm := evidence.RevisionAlgorithmSHA1
		missing := fmt.Sprintf("%040d", 2)
		rootContent := localTreeEntry(t, algorithm, evidence.GitTreeModeRegular, []byte("file"), missing)
		revision := writeLocalRevision(t, directory, algorithm, rootContent)
		result, err := ReadLocalGitRevision(context.Background(), store, revision)
		if !errors.Is(err, LocalGitRevisionObjectUnavailable) || result.RevisionIdentity() != "" {
			t.Fatalf("ReadLocalGitRevision() = (%#v, %v)", result, err)
		}
	})
	t.Run("invalid path", func(t *testing.T) {
		directory, store := newLocalGitObjectStoreFixture(t)
		algorithm := evidence.RevisionAlgorithmSHA1
		blob := writeLooseObject(t, directory, algorithm, "blob", []byte("content"))
		rootContent := localTreeEntry(t, algorithm, evidence.GitTreeModeRegular, []byte("bad\\name"), blob)
		revision := writeLocalRevision(t, directory, algorithm, rootContent)
		result, err := ReadLocalGitRevision(context.Background(), store, revision)
		if !errors.Is(err, LocalGitRevisionInvalidGraph) || result.RevisionIdentity() != "" {
			t.Fatalf("ReadLocalGitRevision() = (%#v, %v)", result, err)
		}
	})
	t.Run("invalid utf8", func(t *testing.T) {
		directory, store := newLocalGitObjectStoreFixture(t)
		algorithm := evidence.RevisionAlgorithmSHA1
		blob := writeLooseObject(t, directory, algorithm, "blob", []byte("content"))
		rootContent := localTreeEntry(t, algorithm, evidence.GitTreeModeRegular, []byte{0xff}, blob)
		revision := writeLocalRevision(t, directory, algorithm, rootContent)
		result, err := ReadLocalGitRevision(context.Background(), store, revision)
		if !errors.Is(err, LocalGitRevisionInvalidGraph) || result.RevisionIdentity() != "" {
			t.Fatalf("ReadLocalGitRevision() = (%#v, %v)", result, err)
		}
	})
}

func TestReadLocalGitRevisionHonorsCancellationAndLimits(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	algorithm := evidence.RevisionAlgorithmSHA1
	blob := writeLooseObject(t, directory, algorithm, "blob", []byte("content"))
	rootContent := localTreeEntry(t, algorithm, evidence.GitTreeModeRegular, []byte("file"), blob)
	revision := writeLocalRevision(t, directory, algorithm, rootContent)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := ReadLocalGitRevision(ctx, store, revision); !errors.Is(err, context.Canceled) || result.RevisionIdentity() != "" {
		t.Fatalf("canceled read = (%#v, %v)", result, err)
	}
	midReadContext := newCancelAfterChecksContext(30)
	if result, err := ReadLocalGitRevision(midReadContext, store, revision); !errors.Is(err, context.Canceled) || result.RevisionIdentity() != "" {
		t.Fatalf("mid-read cancellation = (%#v, %v)", result, err)
	}
	limits := standardLocalGitRevisionLimits()
	limits.maxDepth = 0
	if result, err := readLocalGitRevision(context.Background(), store, revision, limits); !errors.Is(err, LocalGitRevisionResourceLimit) || result.RevisionIdentity() != "" {
		t.Fatalf("limited read = (%#v, %v)", result, err)
	}
	if result, err := ReadLocalGitRevision(nil, store, revision); err == nil || result.RevisionIdentity() != "" {
		t.Fatalf("nil context read = (%#v, %v)", result, err)
	}
	if result, err := ReadLocalGitRevision(context.Background(), nil, revision); !errors.Is(err, LocalGitRevisionInvalidGraph) || result.RevisionIdentity() != "" {
		t.Fatalf("nil store read = (%#v, %v)", result, err)
	}
}

func TestReadLocalGitRevisionRejectsForgedRevision(t *testing.T) {
	_, store := newLocalGitObjectStoreFixture(t)
	result, err := ReadLocalGitRevision(context.Background(), store, evidence.RevisionIdentity{})
	if !errors.Is(err, LocalGitRevisionInvalidGraph) || result.RevisionIdentity() != "" {
		t.Fatalf("ReadLocalGitRevision() = (%#v, %v)", result, err)
	}
}

func writeLocalRevision(t *testing.T, directory string, algorithm evidence.RevisionAlgorithm, rootTreeContent []byte) evidence.RevisionIdentity {
	t.Helper()
	rootDigest := writeLooseObject(t, directory, algorithm, "tree", rootTreeContent)
	commitContent := []byte("tree " + rootDigest + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nmessage\n")
	commitDigest := writeLooseObject(t, directory, algorithm, "commit", commitContent)
	return mustRevisionIdentity(t, algorithm, commitDigest)
}

func localTreeEntry(t *testing.T, algorithm evidence.RevisionAlgorithm, mode evidence.GitTreeMode, name []byte, digest string) []byte {
	t.Helper()
	objectID, err := hex.DecodeString(digest)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	expected := 20
	if algorithm == evidence.RevisionAlgorithmSHA256 {
		expected = 32
	}
	if len(objectID) != expected {
		t.Fatalf("object ID has %d bytes, want %d", len(objectID), expected)
	}
	entry := append([]byte(string(mode)+" "), name...)
	entry = append(entry, 0)
	return append(entry, objectID...)
}
