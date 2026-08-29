package scm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestLocalGitSourceAdapterAcquiresManifestAndContent(t *testing.T) {
	for _, artifact := range []evidence.RepositoryAcquisitionArtifact{evidence.AcquisitionArtifactManifest, evidence.AcquisitionArtifactManifestAndContent} {
		t.Run(string(artifact), func(t *testing.T) {
			directory, store := newLocalGitObjectStoreFixture(t)
			content := []byte("content")
			blob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", content)
			tree := localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte("file"), blob)
			revision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, tree)
			adapter := mustLocalGitSourceAdapter(t, store)
			request := mustLocalGitAdapterRequest(t, adapter, mustRepositoryIdentity(t), revision, artifact)
			result := adapter.Acquire(context.Background(), request)
			if result.Outcome != evidence.AcquisitionOutcomeAcquired || result.Reason != evidence.AcquisitionReasonNone || result.Manifest.FileCount() != 1 {
				t.Fatalf("Acquire() = %#v", result)
			}
			if artifact == evidence.AcquisitionArtifactManifest {
				if result.Contents != nil {
					t.Fatalf("manifest contents = %#v, want nil", result.Contents)
				}
			} else if got := result.Contents["file"]; !bytes.Equal(got, content) {
				t.Fatalf("content = %q, want %q", got, content)
			}
			receipt, err := ExecuteRepositoryAcquisition(context.Background(), request, adapter)
			if err != nil || receipt.Outcome() != evidence.AcquisitionOutcomeAcquired || receipt.ManifestIdentity() != result.Manifest.Identity() {
				t.Fatalf("ExecuteRepositoryAcquisition() = (%#v, %v)", receipt, err)
			}
		})
	}
}

func TestLocalGitSourceAdapterAcquiresEmptyContentSet(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	revision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, nil)
	adapter := mustLocalGitSourceAdapter(t, store)
	request := mustLocalGitAdapterRequest(t, adapter, mustRepositoryIdentity(t), revision, evidence.AcquisitionArtifactManifestAndContent)
	result := adapter.Acquire(context.Background(), request)
	if result.Outcome != evidence.AcquisitionOutcomeAcquired || result.Manifest.FileCount() != 0 || result.Contents == nil || len(result.Contents) != 0 {
		t.Fatalf("Acquire() = %#v", result)
	}
	if receipt, err := ExecuteRepositoryAcquisition(context.Background(), request, adapter); err != nil || receipt.ContentCoverage() != evidence.ContentCoverageComplete {
		t.Fatalf("ExecuteRepositoryAcquisition() = (%#v, %v)", receipt, err)
	}
}

func TestLocalGitSourceAdapterIdentity(t *testing.T) {
	_, store := newLocalGitObjectStoreFixture(t)
	adapter := mustLocalGitSourceAdapter(t, store)
	identity := adapter.Identity()
	wantCapabilities := []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadContent, evidence.SourceCapabilityReadManifest}
	if identity.Kind() != evidence.SourceAdapterKindGit || identity.Name() != "local-git-loose" || identity.Version() != "1.0.0" || !reflect.DeepEqual(identity.Capabilities(), wantCapabilities) {
		t.Fatalf("Identity() = %#v", identity)
	}
	var nilAdapter *LocalGitSourceAdapter
	if nilAdapter.Identity().Identity() != "" {
		t.Fatal("nil adapter returned an identity")
	}
	if result := nilAdapter.Acquire(context.Background(), evidence.RepositoryAcquisitionRequest{}); result.Outcome != evidence.AcquisitionOutcomeFailed || result.Reason != evidence.AcquisitionReasonAdapterFailure {
		t.Fatalf("nil adapter Acquire() = %#v", result)
	}
}

func TestNewLocalGitSourceAdapterRejectsInvalidStore(t *testing.T) {
	for _, store := range []*LocalGitObjectStore{nil, &LocalGitObjectStore{}} {
		if adapter, err := NewLocalGitSourceAdapter(store); err == nil || adapter != nil {
			t.Fatalf("NewLocalGitSourceAdapter() = (%#v, %v)", adapter, err)
		}
	}
}

func TestLocalGitSourceAdapterRejectsMismatchedRequests(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	blob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", []byte("content"))
	tree := localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte("file"), blob)
	revision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, tree)
	adapter := mustLocalGitSourceAdapter(t, store)
	otherRepository, err := evidence.NewRepositoryIdentity("git.example.com", []string{"other"}, "repo")
	if err != nil {
		t.Fatalf("NewRepositoryIdentity() error = %v", err)
	}
	otherAdapter, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "other-git", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest})
	if err != nil {
		t.Fatalf("NewSourceAdapterIdentity() error = %v", err)
	}
	testCases := []evidence.RepositoryAcquisitionRequest{
		mustLocalGitAdapterRequest(t, adapter, otherRepository, revision, evidence.AcquisitionArtifactManifest),
		mustLocalGitAdapterRequestWithIdentity(t, otherAdapter, mustRepositoryIdentity(t), revision, evidence.AcquisitionArtifactManifest),
		{},
	}
	for i, request := range testCases {
		result := adapter.Acquire(context.Background(), request)
		if result.Outcome != evidence.AcquisitionOutcomeFailed || result.Reason != evidence.AcquisitionReasonAdapterFailure || result.Manifest.Identity() != "" || result.Contents != nil {
			t.Fatalf("case %d Acquire() = %#v", i, result)
		}
	}
}

func TestLocalGitSourceAdapterMapsIncompleteArtifacts(t *testing.T) {
	for _, testCase := range []struct {
		name string
		mode evidence.GitTreeMode
	}{
		{name: "missing blob", mode: evidence.GitTreeModeRegular},
		{name: "symlink", mode: evidence.GitTreeModeSymlink},
		{name: "gitlink", mode: evidence.GitTreeModeGitlink},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			directory, store := newLocalGitObjectStoreFixture(t)
			digest := fmt.Sprintf("%040d", 7)
			if testCase.mode == evidence.GitTreeModeSymlink {
				digest = writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", []byte("target"))
			}
			tree := localTreeEntry(t, evidence.RevisionAlgorithmSHA1, testCase.mode, []byte("entry"), digest)
			revision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, tree)
			adapter := mustLocalGitSourceAdapter(t, store)
			request := mustLocalGitAdapterRequest(t, adapter, mustRepositoryIdentity(t), revision, evidence.AcquisitionArtifactManifestAndContent)
			result := adapter.Acquire(context.Background(), request)
			if result.Outcome != evidence.AcquisitionOutcomeFailed || result.Reason != evidence.AcquisitionReasonArtifactIncomplete || result.Manifest.Identity() != "" || result.Contents != nil {
				t.Fatalf("Acquire() = %#v", result)
			}
		})
	}
}

func TestLocalGitSourceAdapterHonorsCancellation(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	blob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", []byte("content"))
	tree := localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte("file"), blob)
	revision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, tree)
	adapter := mustLocalGitSourceAdapter(t, store)
	request := mustLocalGitAdapterRequest(t, adapter, mustRepositoryIdentity(t), revision, evidence.AcquisitionArtifactManifest)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := adapter.Acquire(ctx, request)
	if result.Outcome != evidence.AcquisitionOutcomeFailed || result.Reason != evidence.AcquisitionReasonAdapterFailure {
		t.Fatalf("Acquire() = %#v", result)
	}
	if receipt, err := ExecuteRepositoryAcquisition(ctx, request, adapter); !errors.Is(err, context.Canceled) || receipt.Identity() != "" {
		t.Fatalf("ExecuteRepositoryAcquisition() = (%#v, %v)", receipt, err)
	}
}

func TestLocalGitSourceAdapterDoesNotRetainResults(t *testing.T) {
	directory, store := newLocalGitObjectStoreFixture(t)
	content := []byte("content")
	blob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA256, "blob", content)
	tree := localTreeEntry(t, evidence.RevisionAlgorithmSHA256, evidence.GitTreeModeRegular, []byte("file"), blob)
	revision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA256, tree)
	adapter := mustLocalGitSourceAdapter(t, store)
	request := mustLocalGitAdapterRequest(t, adapter, mustRepositoryIdentity(t), revision, evidence.AcquisitionArtifactManifestAndContent)
	first := adapter.Acquire(context.Background(), request)
	first.Contents["file"][0] = 'X'
	second := adapter.Acquire(context.Background(), request)
	if !bytes.Equal(second.Contents["file"], content) {
		t.Fatalf("second content = %q, want %q", second.Contents["file"], content)
	}
}

func TestLocalGitSourceAdapterFailureMapping(t *testing.T) {
	testCases := []struct {
		err     error
		outcome evidence.RepositoryAcquisitionOutcome
		reason  evidence.RepositoryAcquisitionReason
	}{
		{err: LocalGitRevisionObjectUnavailable, outcome: evidence.AcquisitionOutcomeFailed, reason: evidence.AcquisitionReasonArtifactIncomplete},
		{err: LocalGitRevisionUnsupportedSymlink, outcome: evidence.AcquisitionOutcomeFailed, reason: evidence.AcquisitionReasonArtifactIncomplete},
		{err: LocalGitRevisionUnsupportedGitlink, outcome: evidence.AcquisitionOutcomeFailed, reason: evidence.AcquisitionReasonArtifactIncomplete},
		{err: LocalGitRevisionResourceLimit, outcome: evidence.AcquisitionOutcomeFailed, reason: evidence.AcquisitionReasonResourceLimit},
		{err: LocalGitRevisionInvalidGraph, outcome: evidence.AcquisitionOutcomeFailed, reason: evidence.AcquisitionReasonAdapterFailure},
	}
	for _, testCase := range testCases {
		result := localGitSourceAdapterFailure(testCase.err)
		if result.Outcome != testCase.outcome || result.Reason != testCase.reason || result.Manifest.Identity() != "" || result.Contents != nil {
			t.Fatalf("localGitSourceAdapterFailure(%v) = %#v", testCase.err, result)
		}
	}
}

func mustLocalGitSourceAdapter(t *testing.T, store *LocalGitObjectStore) *LocalGitSourceAdapter {
	t.Helper()
	adapter, err := NewLocalGitSourceAdapter(store)
	if err != nil {
		t.Fatalf("NewLocalGitSourceAdapter() error = %v", err)
	}
	return adapter
}

func mustLocalGitAdapterRequest(t *testing.T, adapter *LocalGitSourceAdapter, repository evidence.RepositoryIdentity, revision evidence.RevisionIdentity, artifact evidence.RepositoryAcquisitionArtifact) evidence.RepositoryAcquisitionRequest {
	t.Helper()
	return mustLocalGitAdapterRequestWithIdentity(t, adapter.Identity(), repository, revision, artifact)
}

func mustLocalGitAdapterRequestWithIdentity(t *testing.T, identity evidence.SourceAdapterIdentity, repository evidence.RepositoryIdentity, revision evidence.RevisionIdentity, artifact evidence.RepositoryAcquisitionArtifact) evidence.RepositoryAcquisitionRequest {
	t.Helper()
	request, err := evidence.NewRepositoryAcquisitionRequest(repository, revision, identity, artifact, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatalf("NewRepositoryAcquisitionRequest() error = %v", err)
	}
	return request
}
