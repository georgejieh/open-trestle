package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestExecuteLocalGitAcquisitionPairBuildsOrderedDelta(t *testing.T) {
	for _, algorithm := range []evidence.RevisionAlgorithm{evidence.RevisionAlgorithmSHA1, evidence.RevisionAlgorithmSHA256} {
		t.Run(string(algorithm), func(t *testing.T) {
			adapter, baseRequest, headRequest, baseContents, headContents := newLocalGitAcquisitionPairFixture(t, algorithm)
			pair, err := ExecuteLocalGitAcquisitionPair(context.Background(), baseRequest, headRequest, adapter)
			if err != nil {
				t.Fatalf("ExecuteLocalGitAcquisitionPair() error = %v", err)
			}
			baseManifest := mustExecutionFixtureWithFiles(t, evidence.AcquisitionArtifactManifestAndContent, baseContents).manifest
			headManifest := mustExecutionFixtureWithFiles(t, evidence.AcquisitionArtifactManifestAndContent, headContents).manifest
			wantDelta, err := evidence.NewRepositoryManifestDelta(baseManifest, headManifest)
			if err != nil {
				t.Fatal(err)
			}
			if pair.Identity() == "" || pair.BaseEnvelope().Identity() == "" || pair.HeadEnvelope().Identity() == "" || !pair.HasManifests() || pair.BaseManifest().Identity() != baseManifest.Identity() || pair.HeadManifest().Identity() != headManifest.Identity() || pair.ManifestDelta().Identity() != wantDelta.Identity() || pair.ManifestDelta().AddedFileCount() != 1 || pair.ManifestDelta().ModifiedFileCount() != 1 || pair.ManifestDelta().RemovedFileCount() != 1 || pair.ManifestDelta().UnchangedFileCount() != 1 {
				t.Fatalf("pair = %#v, want delta %#v", pair, wantDelta)
			}
			if pair.BaseEnvelope().EvidenceBinding().ManifestIdentity() != pair.ManifestDelta().BaseManifestIdentity() || pair.HeadEnvelope().EvidenceBinding().ManifestIdentity() != pair.ManifestDelta().HeadManifestIdentity() || pair.BaseEnvelope().EvidenceBinding().RepositoryIdentity() != pair.HeadEnvelope().EvidenceBinding().RepositoryIdentity() || pair.BaseEnvelope().EvidenceBinding().SourceAdapterIdentity() != pair.HeadEnvelope().EvidenceBinding().SourceAdapterIdentity() || pair.Identity() != expectedLocalGitAcquisitionPairIdentity(pair) {
				t.Fatalf("pair identities do not agree: %#v", pair)
			}
			baseEnvelope, err := ExecuteLocalGitAcquisitionWithBindingAndProfile(context.Background(), baseRequest, adapter)
			if err != nil || baseEnvelope != pair.BaseEnvelope() {
				t.Fatalf("base envelope = (%#v, %v)", baseEnvelope, err)
			}
			headEnvelope, err := ExecuteLocalGitAcquisitionWithBindingAndProfile(context.Background(), headRequest, adapter)
			if err != nil || headEnvelope != pair.HeadEnvelope() {
				t.Fatalf("head envelope = (%#v, %v)", headEnvelope, err)
			}
			reverse, err := ExecuteLocalGitAcquisitionPair(context.Background(), headRequest, baseRequest, adapter)
			if err != nil || reverse.Identity() == pair.Identity() || reverse.BaseEnvelope() != pair.HeadEnvelope() || reverse.HeadEnvelope() != pair.BaseEnvelope() || reverse.ManifestDelta().BaseManifestIdentity() != pair.ManifestDelta().HeadManifestIdentity() || reverse.ManifestDelta().HeadManifestIdentity() != pair.ManifestDelta().BaseManifestIdentity() {
				t.Fatalf("reverse pair = (%#v, %v)", reverse, err)
			}
		})
	}
}

func TestExecuteLocalGitAcquisitionPairAllowsEqualRevisions(t *testing.T) {
	adapter, request, _, _, _ := newLocalGitAcquisitionPairFixture(t, evidence.RevisionAlgorithmSHA1)
	calls := 0
	endpoint := func(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, error) {
		calls++
		return executeLocalGitAcquisitionEnvelopeWithManifest(ctx, request, adapter)
	}
	pair, err := executeLocalGitAcquisitionPairWithEndpoint(context.Background(), request, request, adapter, endpoint)
	if err != nil || calls != 1 || pair.Identity() == "" || pair.BaseEnvelope() != pair.HeadEnvelope() || pair.ManifestDelta().Identity() == "" || pair.ManifestDelta().ChangedFileCount() != 0 || pair.ManifestDelta().BaseManifestIdentity() != pair.ManifestDelta().HeadManifestIdentity() {
		t.Fatalf("equal pair = (%#v, %v), calls = %d", pair, err, calls)
	}
}

func TestExecuteLocalGitAcquisitionPairRejectsRequestsBeforeAcquisition(t *testing.T) {
	adapter, baseRequest, headRequest, _, _ := newLocalGitAcquisitionPairFixture(t, evidence.RevisionAlgorithmSHA1)
	otherRepository, err := evidence.NewRepositoryIdentity("other.example", []string{"owner"}, "repository")
	if err != nil {
		t.Fatal(err)
	}
	otherRequest, err := evidence.NewRepositoryAcquisitionRequest(otherRepository, headRequest.Revision(), adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	manifestOnly, err := evidence.NewRepositoryAcquisitionRequest(headRequest.Repository(), headRequest.Revision(), adapter.Identity(), evidence.AcquisitionArtifactManifest, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	sha256Revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA256, strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	otherAlgorithmRequest, err := evidence.NewRepositoryAcquisitionRequest(headRequest.Repository(), sha256Revision, adapter.Identity(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var nilContext context.Context
	for _, test := range []struct {
		name     string
		ctx      context.Context
		base     evidence.RepositoryAcquisitionRequest
		head     evidence.RepositoryAcquisitionRequest
		adapter  *LocalGitSourceAdapter
		canceled bool
	}{
		{name: "nil context", ctx: nilContext, base: baseRequest, head: headRequest, adapter: adapter},
		{name: "canceled", ctx: ctx, base: baseRequest, head: headRequest, adapter: adapter, canceled: true},
		{name: "nil adapter", ctx: context.Background(), base: baseRequest, head: headRequest},
		{name: "zero base", ctx: context.Background(), head: headRequest, adapter: adapter},
		{name: "zero head", ctx: context.Background(), base: baseRequest, adapter: adapter},
		{name: "repository mismatch", ctx: context.Background(), base: baseRequest, head: otherRequest, adapter: adapter},
		{name: "algorithm mismatch", ctx: context.Background(), base: baseRequest, head: otherAlgorithmRequest, adapter: adapter},
		{name: "manifest only head", ctx: context.Background(), base: baseRequest, head: manifestOnly, adapter: adapter},
	} {
		t.Run(test.name, func(t *testing.T) {
			pair, err := ExecuteLocalGitAcquisitionPair(test.ctx, test.base, test.head, test.adapter)
			if err == nil || pair.Identity() != "" || pair.BaseEnvelope().Identity() != "" || pair.HeadEnvelope().Identity() != "" || pair.ManifestDelta().Identity() != "" {
				t.Fatalf("rejected pair = (%#v, %v)", pair, err)
			}
			if test.canceled && !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestExecuteLocalGitAcquisitionPairReturnsNoPartialHeadFailure(t *testing.T) {
	adapter, baseRequest, _, _, _ := newLocalGitAcquisitionPairFixture(t, evidence.RevisionAlgorithmSHA1)
	missingTree := localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte("missing"), strings.Repeat("8", 40))
	missingRevision := writeLocalRevisionToStore(t, adapter, evidence.RevisionAlgorithmSHA1, missingTree)
	headRequest := mustLocalGitAdapterRequest(t, adapter, baseRequest.Repository(), missingRevision, evidence.AcquisitionArtifactManifestAndContent)
	pair, err := ExecuteLocalGitAcquisitionPair(context.Background(), baseRequest, headRequest, adapter)
	if err == nil || pair.Identity() != "" || pair.BaseEnvelope().Identity() != "" || pair.HeadEnvelope().Identity() != "" || pair.ManifestDelta().Identity() != "" {
		t.Fatalf("head failure pair = (%#v, %v)", pair, err)
	}
}

func TestExecuteLocalGitAcquisitionPairStagesFailuresAtomically(t *testing.T) {
	adapter, baseRequest, headRequest, _, _ := newLocalGitAcquisitionPairFixture(t, evidence.RevisionAlgorithmSHA1)
	t.Run("base failure", func(t *testing.T) {
		calls := 0
		endpoint := func(context.Context, evidence.RepositoryAcquisitionRequest, *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, error) {
			calls++
			return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, errors.New("base failed")
		}
		pair, err := executeLocalGitAcquisitionPairWithEndpoint(context.Background(), baseRequest, headRequest, adapter, endpoint)
		if err == nil || calls != 1 || pair.Identity() != "" {
			t.Fatalf("base failure = (%#v, %v), calls = %d", pair, err, calls)
		}
	})
	t.Run("post-base cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		calls := 0
		endpoint := func(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, error) {
			calls++
			envelope, manifest, err := executeLocalGitAcquisitionEnvelopeWithManifest(ctx, request, adapter)
			cancel()
			return envelope, manifest, err
		}
		pair, err := executeLocalGitAcquisitionPairWithEndpoint(ctx, baseRequest, headRequest, adapter, endpoint)
		if !errors.Is(err, context.Canceled) || calls != 1 || pair.Identity() != "" {
			t.Fatalf("canceled pair = (%#v, %v), calls = %d", pair, err, calls)
		}
	})
	t.Run("head failure", func(t *testing.T) {
		calls := 0
		endpoint := func(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, error) {
			calls++
			if calls == 2 {
				return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, errors.New("head failed")
			}
			return executeLocalGitAcquisitionEnvelopeWithManifest(ctx, request, adapter)
		}
		pair, err := executeLocalGitAcquisitionPairWithEndpoint(context.Background(), baseRequest, headRequest, adapter, endpoint)
		if err == nil || calls != 2 || pair.Identity() != "" || pair.BaseEnvelope().Identity() != "" {
			t.Fatalf("head failure = (%#v, %v), calls = %d", pair, err, calls)
		}
	})
}

func TestNewLocalGitAcquisitionPairRejectsMismatchedChildren(t *testing.T) {
	adapter, baseRequest, headRequest, _, _ := newLocalGitAcquisitionPairFixture(t, evidence.RevisionAlgorithmSHA1)
	pair, err := ExecuteLocalGitAcquisitionPair(context.Background(), baseRequest, headRequest, adapter)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		base  LocalGitAcquisitionEnvelope
		head  LocalGitAcquisitionEnvelope
		delta evidence.RepositoryManifestDelta
	}{
		{name: "zero base", head: pair.HeadEnvelope(), delta: pair.ManifestDelta()},
		{name: "zero head", base: pair.BaseEnvelope(), delta: pair.ManifestDelta()},
		{name: "zero delta", base: pair.BaseEnvelope(), head: pair.HeadEnvelope()},
		{name: "swapped endpoints", base: pair.HeadEnvelope(), head: pair.BaseEnvelope(), delta: pair.ManifestDelta()},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := newLocalGitAcquisitionPair(test.base, test.head, test.delta)
			if err == nil || got.Identity() != "" {
				t.Fatalf("newLocalGitAcquisitionPair() = (%#v, %v)", got, err)
			}
		})
	}
}

func TestClearRepositoryAcquisitionRuntimeResultDropsRetainedBytes(t *testing.T) {
	runtime := repositoryAcquisitionRuntimeResult{
		result: SourceAdapterResult{Contents: map[string][]byte{"file": []byte("content")}},
		bindingInputs: localGitEvidenceInputs{
			commitContent:     []byte("commit"),
			rootTreeContent:   []byte("tree"),
			childTreeContents: map[string][]byte{"tree": []byte("child")},
			blobContents:      map[string][]byte{"blob": []byte("content")},
		},
		hasBindingInputs: true,
	}
	clearRepositoryAcquisitionRuntimeResult(&runtime)
	if !reflect.DeepEqual(runtime, repositoryAcquisitionRuntimeResult{}) {
		t.Fatalf("cleared runtime = %#v", runtime)
	}
	clearRepositoryAcquisitionRuntimeResult(nil)
}

func TestLocalGitAcquisitionPairIsCompact(t *testing.T) {
	assertPairHasNoRawBytes(t, reflect.TypeOf(LocalGitAcquisitionPair{}), "LocalGitAcquisitionPair", map[reflect.Type]bool{})
	var pair LocalGitAcquisitionPair
	if pair.Identity() != "" || pair.BaseEnvelope().Identity() != "" || pair.HeadEnvelope().Identity() != "" || pair.ManifestDelta().Identity() != "" {
		t.Fatalf("zero pair = %#v", pair)
	}
}

func newLocalGitAcquisitionPairFixture(t *testing.T, algorithm evidence.RevisionAlgorithm) (*LocalGitSourceAdapter, evidence.RepositoryAcquisitionRequest, evidence.RepositoryAcquisitionRequest, map[string][]byte, map[string][]byte) {
	t.Helper()
	directory, store := newLocalGitObjectStoreFixture(t)
	baseContents := map[string][]byte{"changed.go": []byte("old\n"), "removed.go": []byte("removed\n"), "same.go": []byte("same\n")}
	headContents := map[string][]byte{"added.go": []byte("added\n"), "changed.go": []byte("new\n"), "same.go": []byte("same\n")}
	baseTree := pairTreeContent(t, directory, algorithm, baseContents)
	headTree := pairTreeContent(t, directory, algorithm, headContents)
	baseRevision := writeLocalRevision(t, directory, algorithm, baseTree)
	headRevision := writeLocalRevision(t, directory, algorithm, headTree)
	adapter := mustLocalGitSourceAdapter(t, store)
	repository := mustRepositoryIdentity(t)
	baseRequest := mustLocalGitAdapterRequest(t, adapter, repository, baseRevision, evidence.AcquisitionArtifactManifestAndContent)
	headRequest := mustLocalGitAdapterRequest(t, adapter, repository, headRevision, evidence.AcquisitionArtifactManifestAndContent)
	return adapter, baseRequest, headRequest, baseContents, headContents
}

func pairTreeContent(t *testing.T, directory string, algorithm evidence.RevisionAlgorithm, contents map[string][]byte) []byte {
	t.Helper()
	paths := []string{"added.go", "changed.go", "removed.go", "same.go"}
	var tree []byte
	for _, path := range paths {
		content, exists := contents[path]
		if !exists {
			continue
		}
		blob := writeLooseObject(t, directory, algorithm, "blob", content)
		tree = append(tree, localTreeEntry(t, algorithm, evidence.GitTreeModeRegular, []byte(path), blob)...)
	}
	return tree
}

func writeLocalRevisionToStore(t *testing.T, adapter *LocalGitSourceAdapter, algorithm evidence.RevisionAlgorithm, tree []byte) evidence.RevisionIdentity {
	t.Helper()
	rootName := adapter.store.objectsRoot.Name()
	if rootName == "" {
		t.Fatal("object root name is empty")
	}
	return writeLocalRevision(t, rootName, algorithm, tree)
}

func expectedLocalGitAcquisitionPairIdentity(pair LocalGitAcquisitionPair) string {
	preimage := struct {
		Contract                        string `json:"contract"`
		SchemaVersion                   int    `json:"schema_version"`
		BaseAcquisitionEnvelopeIdentity string `json:"base_acquisition_envelope_identity"`
		HeadAcquisitionEnvelopeIdentity string `json:"head_acquisition_envelope_identity"`
		RepositoryManifestDeltaIdentity string `json:"repository_manifest_delta_identity"`
	}{"open-trestle/local-git-acquisition-pair", 1, pair.BaseEnvelope().Identity(), pair.HeadEnvelope().Identity(), pair.ManifestDelta().Identity()}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func assertPairHasNoRawBytes(t *testing.T, value reflect.Type, path string, seen map[reflect.Type]bool) {
	t.Helper()
	if seen[value] {
		return
	}
	seen[value] = true
	switch value.Kind() {
	case reflect.Map, reflect.Pointer, reflect.Interface:
		t.Fatalf("%s retains %s", path, value)
	case reflect.Slice, reflect.Array:
		if value.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("%s retains bytes", path)
		}
		assertPairHasNoRawBytes(t, value.Elem(), path+"[]", seen)
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			assertPairHasNoRawBytes(t, field.Type, path+"."+field.Name, seen)
		}
	}
}
