package scm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"testing"

	"github.com/georgejieh/open-trestle/internal/analysis"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestExecuteLocalGitChangeWithGoImpactBuildsExactProfile(t *testing.T) {
	base := []byte("package sample\n\nfunc target() {\n\tprintln(\"old\")\n}\n")
	head := []byte("package sample\n\nfunc target() {\n\tprintln(\"new\")\n}\n")
	adapter, baseRequest, headRequest := newSinglePathNamedLocalGitChangeFixture(t, "file.go", base, head)
	execution, err := ExecuteLocalGitChangeWithGoImpact(context.Background(), baseRequest, headRequest, adapter)
	if err != nil {
		t.Fatal(err)
	}
	changeExecution, err := ExecuteLocalGitChange(context.Background(), baseRequest, headRequest, adapter)
	if err != nil {
		t.Fatal(err)
	}
	wantProfile, wantReceipt, err := analysis.BuildGoChangeImpactProfile(changeExecution.Change(), map[string][]byte{"file.go": head})
	if err != nil {
		t.Fatal(err)
	}
	if execution.Identity() == "" || !execution.HasImpact() || execution.ChangeExecution().Identity() != changeExecution.Identity() || execution.Profile().Identity() != wantProfile.Identity() || execution.Receipt().Identity() != wantReceipt.Identity() || execution.Receipt().ChangeIdentity() != changeExecution.Change().Identity() || execution.Identity() != expectedLocalGitGoImpactExecutionIdentity(execution) {
		t.Fatalf("execution = %#v", execution)
	}
	coverage, ok := execution.Receipt().File("file.go")
	if !ok || coverage.Outcome() != analysis.GoImpactOutcomeAnalyzed || coverage.Reason() != analysis.GoImpactReasonNone || coverage.SymbolCount() != 1 || len(execution.Profile().Symbols()) != 1 {
		t.Fatalf("coverage = (%#v, %v), profile = %#v", coverage, ok, execution.Profile())
	}
}

func TestExecuteLocalGitChangeWithGoImpactRecordsNonGoCoverage(t *testing.T) {
	adapter, baseRequest, headRequest := newSinglePathNamedLocalGitChangeFixture(t, "file.txt", []byte("old\n"), []byte("new\n"))
	execution, err := ExecuteLocalGitChangeWithGoImpact(context.Background(), baseRequest, headRequest, adapter)
	if err != nil || !execution.HasImpact() || len(execution.Profile().Symbols()) != 0 {
		t.Fatalf("execution = (%#v, %v)", execution, err)
	}
	coverage, ok := execution.Receipt().File("file.txt")
	if !ok || coverage.Outcome() != analysis.GoImpactOutcomeUnsupported || coverage.Reason() != analysis.GoImpactReasonUnsupportedLanguage || coverage.SymbolCount() != 0 {
		t.Fatalf("coverage = (%#v, %v)", coverage, ok)
	}
}

func TestExecuteLocalGitChangeWithGoImpactAllowsAbsentChange(t *testing.T) {
	adapter, request, _, _, _ := newLocalGitAcquisitionPairFixture(t, evidence.RevisionAlgorithmSHA1)
	builderCalls := 0
	builder := func(change evidence.Change, contents map[string][]byte) (analysis.ChangeImpactProfile, analysis.GoChangeImpactReceipt, error) {
		builderCalls++
		return analysis.ChangeImpactProfile{}, analysis.GoChangeImpactReceipt{}, errors.New("unexpected builder call")
	}
	execution, err := executeLocalGitChangeWithGoImpact(context.Background(), request, request, adapter, executeLocalGitAcquisitionEnvelopeWithOwnedContent, evidence.ExecuteRepositoryFileDelta, builder)
	if err != nil || builderCalls != 0 || execution.Identity() == "" || execution.ChangeExecution().Identity() == "" || execution.ChangeExecution().HasChange() || execution.HasImpact() || execution.Profile().Identity() != "" || execution.Receipt().Identity() != "" || execution.Identity() != expectedLocalGitGoImpactExecutionIdentity(execution) {
		t.Fatalf("absent impact execution = (%#v, %v), builder calls = %d", execution, err, builderCalls)
	}
}

func TestExecuteLocalGitChangeWithGoImpactTransfersOnlySupportedGoHeads(t *testing.T) {
	baseGo := []byte("package sample\nfunc target() { println(\"old\") }\n")
	headGo := []byte("package sample\nfunc target() { println(\"new\") }\n")
	base := map[string][]byte{
		"file.go":    baseGo,
		"file.txt":   []byte("old\n"),
		"removed.go": []byte("package sample\nfunc removed() {}\n"),
	}
	head := map[string][]byte{
		"added.go": []byte("package sample\nfunc added() {}\n"),
		"file.go":  headGo,
		"file.txt": []byte("new\n"),
	}
	adapter, baseRequest, headRequest := newContentMapLocalGitChangeFixture(t, base, head)
	builderCalls := 0
	builder := func(change evidence.Change, contents map[string][]byte) (analysis.ChangeImpactProfile, analysis.GoChangeImpactReceipt, error) {
		builderCalls++
		if len(contents) != 2 || !bytes.Equal(contents["added.go"], head["added.go"]) || !bytes.Equal(contents["file.go"], headGo) {
			return analysis.ChangeImpactProfile{}, analysis.GoChangeImpactReceipt{}, errors.New("unexpected Go head content")
		}
		return analysis.BuildGoChangeImpactProfile(change, contents)
	}
	execution, err := executeLocalGitChangeWithGoImpact(context.Background(), baseRequest, headRequest, adapter, executeLocalGitAcquisitionEnvelopeWithOwnedContent, evidence.ExecuteRepositoryFileDelta, builder)
	if err != nil || builderCalls != 1 || !execution.HasImpact() {
		t.Fatalf("execution = (%#v, %v), builder calls = %d", execution, err, builderCalls)
	}
	if coverage, ok := execution.Receipt().File("file.txt"); !ok || coverage.Outcome() != analysis.GoImpactOutcomeUnsupported {
		t.Fatalf("non-Go coverage = (%#v, %v)", coverage, ok)
	}
	if _, ok := execution.Receipt().File("added.go"); !ok {
		t.Fatal("supported added Go file missing from Change impact receipt")
	}
	if _, ok := execution.Receipt().File("removed.go"); ok {
		t.Fatal("unsupported removed Go file appeared in Change impact receipt")
	}
}

func TestExecuteLocalGitChangeWithGoImpactClearsTransferredHeadBytes(t *testing.T) {
	base := []byte("package sample\nfunc target() { println(\"old\") }\n")
	head := []byte("package sample\nfunc target() { println(\"new\") }\n")
	adapter, baseRequest, headRequest := newSinglePathNamedLocalGitChangeFixture(t, "file.go", base, head)
	var acquiredHeadAlias []byte
	var builderAlias []byte
	var builderMap map[string][]byte
	calls := 0
	endpoint := func(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, map[string][]byte, error) {
		calls++
		envelope, manifest, contents, err := executeLocalGitAcquisitionEnvelopeWithOwnedContent(ctx, request, adapter)
		if calls == 2 && err == nil {
			acquiredHeadAlias = contents["file.go"]
		}
		return envelope, manifest, contents, err
	}
	builder := func(change evidence.Change, contents map[string][]byte) (analysis.ChangeImpactProfile, analysis.GoChangeImpactReceipt, error) {
		builderMap = contents
		builderAlias = contents["file.go"]
		return analysis.BuildGoChangeImpactProfile(change, contents)
	}
	execution, err := executeLocalGitChangeWithGoImpact(context.Background(), baseRequest, headRequest, adapter, endpoint, evidence.ExecuteRepositoryFileDelta, builder)
	if err != nil || execution.Identity() == "" || execution.Profile().Identity() == "" || calls != 2 {
		t.Fatalf("execution = (%#v, %v), calls = %d", execution, err, calls)
	}
	profileIdentity := execution.Profile().Identity()
	if len(acquiredHeadAlias) == 0 || len(builderAlias) == 0 || len(builderMap) != 0 || !allZeroBytes(acquiredHeadAlias) || !allZeroBytes(builderAlias) || execution.Profile().Identity() != profileIdentity {
		t.Fatalf("head content remained: map=%#v acquired=%q builder=%q", builderMap, acquiredHeadAlias, builderAlias)
	}
}

func TestExecuteLocalGitChangeWithGoImpactClearsHeadOnBuilderError(t *testing.T) {
	base := []byte("package sample\nfunc target() { println(\"old\") }\n")
	head := []byte("package sample\nfunc target() { println(\"new\") }\n")
	adapter, baseRequest, headRequest := newSinglePathNamedLocalGitChangeFixture(t, "file.go", base, head)
	var alias []byte
	builderError := errors.New("builder failed")
	builder := func(change evidence.Change, contents map[string][]byte) (analysis.ChangeImpactProfile, analysis.GoChangeImpactReceipt, error) {
		alias = contents["file.go"]
		return analysis.ChangeImpactProfile{}, analysis.GoChangeImpactReceipt{}, builderError
	}
	execution, err := executeLocalGitChangeWithGoImpact(context.Background(), baseRequest, headRequest, adapter, executeLocalGitAcquisitionEnvelopeWithOwnedContent, evidence.ExecuteRepositoryFileDelta, builder)
	if !errors.Is(err, builderError) || execution.Identity() != "" || len(alias) == 0 || !allZeroBytes(alias) {
		t.Fatalf("failed execution = (%#v, %v), alias = %q", execution, err, alias)
	}
}

func TestLocalGitGoImpactExecutionIsCompactAndIdentityBound(t *testing.T) {
	base := []byte("package sample\nfunc target() { println(\"old\") }\n")
	head := []byte("package sample\nfunc target() { println(\"new\") }\n")
	adapter, baseRequest, headRequest := newSinglePathNamedLocalGitChangeFixture(t, "file.go", base, head)
	execution, err := ExecuteLocalGitChangeWithGoImpact(context.Background(), baseRequest, headRequest, adapter)
	if err != nil || execution.Identity() == "" || execution.Identity() != expectedLocalGitGoImpactExecutionIdentity(execution) {
		t.Fatalf("execution = (%#v, %v)", execution, err)
	}
	assertGoImpactExecutionHasNoRawBytes(t, reflect.TypeOf(LocalGitGoImpactExecution{}), "LocalGitGoImpactExecution", map[reflect.Type]bool{})
	var zero LocalGitGoImpactExecution
	if zero.Identity() != "" || zero.ChangeExecution().Identity() != "" || zero.HasImpact() || zero.Profile().Identity() != "" || zero.Receipt().Identity() != "" {
		t.Fatalf("zero execution = %#v", zero)
	}
}

func newContentMapLocalGitChangeFixture(t *testing.T, baseContents, headContents map[string][]byte) (*LocalGitSourceAdapter, evidence.RepositoryAcquisitionRequest, evidence.RepositoryAcquisitionRequest) {
	t.Helper()
	directory, store := newLocalGitObjectStoreFixture(t)
	baseRevision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, goImpactTreeContent(t, directory, baseContents))
	headRevision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, goImpactTreeContent(t, directory, headContents))
	adapter := mustLocalGitSourceAdapter(t, store)
	repository := mustRepositoryIdentity(t)
	return adapter,
		mustLocalGitAdapterRequest(t, adapter, repository, baseRevision, evidence.AcquisitionArtifactManifestAndContent),
		mustLocalGitAdapterRequest(t, adapter, repository, headRevision, evidence.AcquisitionArtifactManifestAndContent)
}

func goImpactTreeContent(t *testing.T, directory string, contents map[string][]byte) []byte {
	t.Helper()
	paths := make([]string, 0, len(contents))
	for path := range contents {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var tree []byte
	for _, path := range paths {
		blob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", contents[path])
		tree = append(tree, localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte(path), blob)...)
	}
	return tree
}

func newSinglePathNamedLocalGitChangeFixture(t *testing.T, name string, baseContent, headContent []byte) (*LocalGitSourceAdapter, evidence.RepositoryAcquisitionRequest, evidence.RepositoryAcquisitionRequest) {
	t.Helper()
	directory, store := newLocalGitObjectStoreFixture(t)
	baseBlob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", baseContent)
	headBlob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", headContent)
	baseRevision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte(name), baseBlob))
	headRevision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte(name), headBlob))
	adapter := mustLocalGitSourceAdapter(t, store)
	repository := mustRepositoryIdentity(t)
	return adapter,
		mustLocalGitAdapterRequest(t, adapter, repository, baseRevision, evidence.AcquisitionArtifactManifestAndContent),
		mustLocalGitAdapterRequest(t, adapter, repository, headRevision, evidence.AcquisitionArtifactManifestAndContent)
}

func expectedLocalGitGoImpactExecutionIdentity(execution LocalGitGoImpactExecution) string {
	preimage := struct {
		Contract                string `json:"contract"`
		SchemaVersion           int    `json:"schema_version"`
		ChangeExecutionIdentity string `json:"change_execution_identity"`
		ImpactPresent           bool   `json:"impact_present"`
		ProfileIdentity         string `json:"profile_identity"`
		ReceiptIdentity         string `json:"receipt_identity"`
	}{"open-trestle/local-git-go-impact-execution", 1, execution.ChangeExecution().Identity(), execution.HasImpact(), execution.Profile().Identity(), execution.Receipt().Identity()}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func allZeroBytes(content []byte) bool {
	for _, value := range content {
		if value != 0 {
			return false
		}
	}
	return true
}

func assertGoImpactExecutionHasNoRawBytes(t *testing.T, value reflect.Type, path string, seen map[reflect.Type]bool) {
	t.Helper()
	if seen[value] {
		return
	}
	seen[value] = true
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		t.Fatalf("%s retains %s", path, value)
	case reflect.Map:
		assertGoImpactExecutionHasNoRawBytes(t, value.Key(), path+".key", seen)
		assertGoImpactExecutionHasNoRawBytes(t, value.Elem(), path+".value", seen)
	case reflect.Slice, reflect.Array:
		if value.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("%s retains bytes", path)
		}
		assertGoImpactExecutionHasNoRawBytes(t, value.Elem(), path+"[]", seen)
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			assertGoImpactExecutionHasNoRawBytes(t, field.Type, path+"."+field.Name, seen)
		}
	}
}
