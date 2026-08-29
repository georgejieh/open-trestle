package scm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestExecuteLocalGitChangeBuildsAccountedChange(t *testing.T) {
	for _, algorithm := range []evidence.RevisionAlgorithm{evidence.RevisionAlgorithmSHA1, evidence.RevisionAlgorithmSHA256} {
		t.Run(string(algorithm), func(t *testing.T) {
			adapter, baseRequest, headRequest, baseContents, headContents := newLocalGitAcquisitionPairFixture(t, algorithm)
			acquisitionCalls, fileCalls := 0, 0
			endpoint := func(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, map[string][]byte, error) {
				acquisitionCalls++
				return executeLocalGitAcquisitionEnvelopeWithOwnedContent(ctx, request, adapter)
			}
			fileExecutor := func(entry evidence.RepositoryFileDelta, base, head evidence.RepositoryFileDeltaContent) (evidence.RepositoryFileDeltaExecution, error) {
				fileCalls++
				return evidence.ExecuteRepositoryFileDelta(entry, base, head)
			}
			execution, err := executeLocalGitChange(context.Background(), baseRequest, headRequest, adapter, endpoint, fileExecutor)
			if err != nil || acquisitionCalls != 2 || fileCalls != 3 {
				t.Fatalf("ExecuteLocalGitChange() = (%#v, %v), acquisition calls = %d, file calls = %d", execution, err, acquisitionCalls, fileCalls)
			}
			pair, err := ExecuteLocalGitAcquisitionPair(context.Background(), baseRequest, headRequest, adapter)
			if err != nil || execution.AcquisitionPair().Identity() != pair.Identity() {
				t.Fatalf("pair = (%#v, %v), execution %#v", pair, err, execution)
			}
			patch, _ := evidence.GenerateUnifiedFileDiff("changed.go", baseContents["changed.go"], headContents["changed.go"])
			fileChange, lineMap, _ := evidence.ParseUnifiedFileDiff("changed.go", baseContents["changed.go"], headContents["changed.go"], patch)
			wantChange, _ := evidence.NewChange([]evidence.FileChange{fileChange}, []evidence.LineMap{lineMap})
			entries := execution.EntryExecutions()
			if execution.Identity() == "" || !execution.HasChange() || execution.Change().Identity() != wantChange.Identity() || len(entries) != 3 || len(entries) != pair.ManifestDelta().ChangedFileCount() || execution.Identity() != expectedLocalGitChangeExecutionIdentity(execution) {
				t.Fatalf("execution = %#v, entries = %#v", execution, entries)
			}
			wantPaths := []string{"added.go", "changed.go", "removed.go"}
			wantStatuses := []evidence.RepositoryFileDeltaExecutionStatus{evidence.RepositoryFileDeltaExecutionStatusUnsupported, evidence.RepositoryFileDeltaExecutionStatusSupported, evidence.RepositoryFileDeltaExecutionStatusUnsupported}
			wantReasons := []evidence.RepositoryFileDeltaUnsupportedReason{evidence.RepositoryFileDeltaUnsupportedReasonAddedFile, evidence.RepositoryFileDeltaUnsupportedReasonNone, evidence.RepositoryFileDeltaUnsupportedReasonRemovedFile}
			for i, entryExecution := range entries {
				deltaEntry, ok := pair.ManifestDelta().Entry(wantPaths[i])
				if !ok || entryExecution.Identity() == "" || entryExecution.Path() != wantPaths[i] || entryExecution.RepositoryFileDeltaIdentity() != deltaEntry.Identity() || entryExecution.Status() != wantStatuses[i] || entryExecution.Reason() != wantReasons[i] {
					t.Fatalf("entry execution %d = %#v", i, entryExecution)
				}
			}
			if entries[1].FileChange().Identity() != fileChange.Identity() || entries[1].LineMap().Identity() != lineMap.Identity() || entries[0].FileChange().Identity() != "" || entries[2].LineMap().Identity() != "" {
				t.Fatalf("entry evidence = %#v", entries)
			}
		})
	}
}

func TestExecuteLocalGitChangePreservesOpaqueRefusals(t *testing.T) {
	for _, test := range []struct {
		name string
		base []byte
		head []byte
		want evidence.RepositoryFileDeltaUnsupportedReason
	}{
		{name: "NUL", base: []byte{'a', 0}, head: []byte{'b', 0}, want: evidence.RepositoryFileDeltaUnsupportedReasonContent},
		{name: "resource", base: bytes.Repeat([]byte("base\n"), 513), head: bytes.Repeat([]byte("head\n"), 513), want: evidence.RepositoryFileDeltaUnsupportedReasonResourceLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, baseRequest, headRequest := newSinglePathLocalGitChangeFixture(t, test.base, test.head)
			execution, err := ExecuteLocalGitChange(context.Background(), baseRequest, headRequest, adapter)
			entries := execution.EntryExecutions()
			if err != nil || execution.Identity() == "" || execution.HasChange() || execution.Change().Identity() != "" || len(entries) != 1 || entries[0].Status() != evidence.RepositoryFileDeltaExecutionStatusUnsupported || entries[0].Reason() != test.want {
				t.Fatalf("execution = (%#v, %v), entries = %#v", execution, err, entries)
			}
		})
	}
}

func TestExecuteLocalGitChangeAcceptsEqualRevisions(t *testing.T) {
	adapter, request, _, _, _ := newLocalGitAcquisitionPairFixture(t, evidence.RevisionAlgorithmSHA1)
	acquisitionCalls, fileCalls := 0, 0
	endpoint := func(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, map[string][]byte, error) {
		acquisitionCalls++
		return executeLocalGitAcquisitionEnvelopeWithOwnedContent(ctx, request, adapter)
	}
	fileExecutor := func(entry evidence.RepositoryFileDelta, base, head evidence.RepositoryFileDeltaContent) (evidence.RepositoryFileDeltaExecution, error) {
		fileCalls++
		return evidence.ExecuteRepositoryFileDelta(entry, base, head)
	}
	execution, err := executeLocalGitChange(context.Background(), request, request, adapter, endpoint, fileExecutor)
	if err != nil || acquisitionCalls != 1 || fileCalls != 0 || execution.Identity() == "" || execution.HasChange() || execution.Change().Identity() != "" || execution.EntryExecutions() != nil || execution.AcquisitionPair().ManifestDelta().Identity() == "" || execution.AcquisitionPair().ManifestDelta().ChangedFileCount() != 0 {
		t.Fatalf("equal execution = (%#v, %v), acquisition calls = %d, file calls = %d", execution, err, acquisitionCalls, fileCalls)
	}
}

func TestExecuteLocalGitChangeAcceptsEntryLimit(t *testing.T) {
	adapter, baseRequest, headRequest := newManyPathLocalGitChangeFixture(t, maxLocalGitChangeEntries)
	execution, err := ExecuteLocalGitChange(context.Background(), baseRequest, headRequest, adapter)
	if err != nil || execution.Identity() == "" || !execution.HasChange() || len(execution.EntryExecutions()) != maxLocalGitChangeEntries || len(execution.Change().FileChanges()) != maxLocalGitChangeEntries {
		t.Fatalf("limit execution = (%#v, %v)", execution, err)
	}
}

func TestExecuteLocalGitChangeBoundsBatchEntriesBeforeFileWork(t *testing.T) {
	adapter, baseRequest, headRequest := newManyPathLocalGitChangeFixture(t, maxLocalGitChangeEntries+1)
	acquisitionCalls, fileCalls := 0, 0
	endpoint := func(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, map[string][]byte, error) {
		acquisitionCalls++
		return executeLocalGitAcquisitionEnvelopeWithOwnedContent(ctx, request, adapter)
	}
	fileExecutor := func(entry evidence.RepositoryFileDelta, base, head evidence.RepositoryFileDeltaContent) (evidence.RepositoryFileDeltaExecution, error) {
		fileCalls++
		return evidence.ExecuteRepositoryFileDelta(entry, base, head)
	}
	execution, err := executeLocalGitChange(context.Background(), baseRequest, headRequest, adapter, endpoint, fileExecutor)
	if !errors.Is(err, LocalGitChangeExecutionResourceLimit) || acquisitionCalls != 2 || fileCalls != 0 || execution.Identity() != "" || execution.AcquisitionPair().Identity() != "" || execution.EntryExecutions() != nil {
		t.Fatalf("bounded execution = (%#v, %v), acquisition calls = %d, file calls = %d", execution, err, acquisitionCalls, fileCalls)
	}
}

func TestExecuteLocalGitChangeReturnsZeroOnAcquisitionFailure(t *testing.T) {
	adapter, baseRequest, _, _, _ := newLocalGitAcquisitionPairFixture(t, evidence.RevisionAlgorithmSHA1)
	missingTree := localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte("missing"), strings.Repeat("8", 40))
	missingRevision := writeLocalRevisionToStore(t, adapter, evidence.RevisionAlgorithmSHA1, missingTree)
	headRequest := mustLocalGitAdapterRequest(t, adapter, baseRequest.Repository(), missingRevision, evidence.AcquisitionArtifactManifestAndContent)
	execution, err := ExecuteLocalGitChange(context.Background(), baseRequest, headRequest, adapter)
	if err == nil || execution.Identity() != "" || execution.AcquisitionPair().Identity() != "" || execution.EntryExecutions() != nil {
		t.Fatalf("failed execution = (%#v, %v)", execution, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	execution, err = ExecuteLocalGitChange(ctx, baseRequest, baseRequest, adapter)
	if !errors.Is(err, context.Canceled) || execution.Identity() != "" {
		t.Fatalf("canceled execution = (%#v, %v)", execution, err)
	}
}

func TestLocalGitChangeExecutionIsCompactAndDefensive(t *testing.T) {
	adapter, baseRequest, headRequest := newSinglePathLocalGitChangeFixture(t, []byte("old\n"), []byte("new\n"))
	execution, err := ExecuteLocalGitChange(context.Background(), baseRequest, headRequest, adapter)
	if err != nil {
		t.Fatal(err)
	}
	assertLocalGitChangeExecutionCompact(t, reflect.TypeOf(LocalGitChangeExecution{}), "LocalGitChangeExecution", map[reflect.Type]bool{})
	entries := execution.EntryExecutions()
	entries[0] = evidence.RepositoryFileDeltaExecution{}
	if execution.EntryExecutions()[0].Identity() == "" {
		t.Fatal("returned entry execution slice aliases stored state")
	}
	var zero LocalGitChangeExecution
	if zero.Identity() != "" || zero.AcquisitionPair().Identity() != "" || zero.HasChange() || zero.Change().Identity() != "" || zero.EntryExecutions() != nil {
		t.Fatalf("zero execution = %#v", zero)
	}
}

func TestClearLocalGitChangeContentsDropsReferences(t *testing.T) {
	contents := map[string][]byte{"a": []byte("a"), "b": []byte("b")}
	clearLocalGitChangeContents(contents)
	if len(contents) != 0 {
		t.Fatalf("contents = %#v", contents)
	}
	clearLocalGitChangeContents(nil)
}

func newManyPathLocalGitChangeFixture(t *testing.T, count int) (*LocalGitSourceAdapter, evidence.RepositoryAcquisitionRequest, evidence.RepositoryAcquisitionRequest) {
	t.Helper()
	directory, store := newLocalGitObjectStoreFixture(t)
	baseBlob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", []byte("base\n"))
	headBlob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", []byte("head\n"))
	var baseTree, headTree []byte
	for i := 0; i < count; i++ {
		path := []byte(fmt.Sprintf("file-%03d.txt", i))
		baseTree = append(baseTree, localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, path, baseBlob)...)
		headTree = append(headTree, localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, path, headBlob)...)
	}
	baseRevision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, baseTree)
	headRevision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, headTree)
	adapter := mustLocalGitSourceAdapter(t, store)
	repository := mustRepositoryIdentity(t)
	return adapter,
		mustLocalGitAdapterRequest(t, adapter, repository, baseRevision, evidence.AcquisitionArtifactManifestAndContent),
		mustLocalGitAdapterRequest(t, adapter, repository, headRevision, evidence.AcquisitionArtifactManifestAndContent)
}

func newSinglePathLocalGitChangeFixture(t *testing.T, baseContent, headContent []byte) (*LocalGitSourceAdapter, evidence.RepositoryAcquisitionRequest, evidence.RepositoryAcquisitionRequest) {
	t.Helper()
	directory, store := newLocalGitObjectStoreFixture(t)
	baseBlob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", baseContent)
	headBlob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", headContent)
	baseRevision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte("file.txt"), baseBlob))
	headRevision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte("file.txt"), headBlob))
	adapter := mustLocalGitSourceAdapter(t, store)
	repository := mustRepositoryIdentity(t)
	return adapter,
		mustLocalGitAdapterRequest(t, adapter, repository, baseRevision, evidence.AcquisitionArtifactManifestAndContent),
		mustLocalGitAdapterRequest(t, adapter, repository, headRevision, evidence.AcquisitionArtifactManifestAndContent)
}

func expectedLocalGitChangeExecutionIdentity(execution LocalGitChangeExecution) string {
	type entryWire struct {
		Path     string `json:"path"`
		Identity string `json:"identity"`
	}
	entries := execution.EntryExecutions()
	preimage := struct {
		Contract                string      `json:"contract"`
		SchemaVersion           int         `json:"schema_version"`
		AcquisitionPairIdentity string      `json:"acquisition_pair_identity"`
		ChangePresent           bool        `json:"change_present"`
		ChangeIdentity          string      `json:"change_identity"`
		EntryExecutions         []entryWire `json:"entry_executions"`
	}{"open-trestle/local-git-change-execution", 1, execution.AcquisitionPair().Identity(), execution.HasChange(), execution.Change().Identity(), make([]entryWire, len(entries))}
	for i, entry := range entries {
		preimage.EntryExecutions[i] = entryWire{entry.Path(), entry.Identity()}
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func assertLocalGitChangeExecutionCompact(t *testing.T, value reflect.Type, path string, seen map[reflect.Type]bool) {
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
		assertLocalGitChangeExecutionCompact(t, value.Elem(), path+"[]", seen)
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			assertLocalGitChangeExecutionCompact(t, field.Type, path+"."+field.Name, seen)
		}
	}
}
