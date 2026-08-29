package scm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

func TestExecuteLocalGitChangeWithDebugOutputReviewBuildsExactResult(t *testing.T) {
	base := []byte("package sample\nfunc target() {}\n")
	head := []byte("package sample\nimport \"fmt\"\nfunc target() { fmt.Println(\"debug\") }\n")
	adapter, baseRequest, headRequest := newSinglePathNamedLocalGitChangeFixture(t, "file.go", base, head)
	limits := testDebugOutputReviewLimits()
	execution, err := ExecuteLocalGitChangeWithDebugOutputReview(context.Background(), baseRequest, headRequest, adapter, limits)
	if err != nil {
		t.Fatal(err)
	}
	changeExecution, err := ExecuteLocalGitChange(context.Background(), baseRequest, headRequest, adapter)
	if err != nil {
		t.Fatal(err)
	}
	want, err := review.ReviewDebugOutputChange(changeExecution.Change(), map[string][]byte{"file.go": head}, limits)
	if err != nil {
		t.Fatal(err)
	}
	if execution.Identity() == "" || !execution.HasReview() || execution.ChangeExecution().Identity() != changeExecution.Identity() || execution.Result().Identity() != want.Identity() || execution.Result().ChangeIdentity() != changeExecution.Change().Identity() || execution.Identity() != expectedLocalGitDebugOutputReviewExecutionIdentity(execution) || len(execution.Result().Findings()) != 1 {
		t.Fatalf("execution = %#v", execution)
	}
}

func TestExecuteLocalGitChangeWithDebugOutputReviewRecordsNonGoCoverage(t *testing.T) {
	adapter, baseRequest, headRequest := newSinglePathNamedLocalGitChangeFixture(t, "file.txt", []byte("old\n"), []byte("new\n"))
	execution, err := ExecuteLocalGitChangeWithDebugOutputReview(context.Background(), baseRequest, headRequest, adapter, testDebugOutputReviewLimits())
	if err != nil || !execution.HasReview() || len(execution.Result().Findings()) != 0 {
		t.Fatalf("execution = (%#v, %v)", execution, err)
	}
	coverage, ok := execution.Result().File("file.txt")
	if !ok || coverage.Outcome() != review.DebugOutputChangeOutcomeNotApplicable || coverage.Reason() != review.DebugOutputChangeReasonUnsupportedLanguage {
		t.Fatalf("coverage = (%#v, %v)", coverage, ok)
	}
}

func TestExecuteLocalGitChangeWithDebugOutputReviewAllowsAbsentChange(t *testing.T) {
	adapter, request, _, _, _ := newLocalGitAcquisitionPairFixture(t, evidence.RevisionAlgorithmSHA1)
	builderCalls := 0
	builder := func(change evidence.Change, contents map[string][]byte, limits review.DebugOutputChangeLimits) (review.DebugOutputChangeResult, error) {
		builderCalls++
		return review.DebugOutputChangeResult{}, errors.New("unexpected builder call")
	}
	execution, err := executeLocalGitChangeWithDebugOutputReview(context.Background(), request, request, adapter, testDebugOutputReviewLimits(), executeLocalGitAcquisitionEnvelopeWithOwnedContent, evidence.ExecuteRepositoryFileDelta, builder)
	if err != nil || builderCalls != 0 || execution.Identity() == "" || execution.ChangeExecution().HasChange() || execution.HasReview() || execution.Result().Identity() != "" || execution.Identity() != expectedLocalGitDebugOutputReviewExecutionIdentity(execution) {
		t.Fatalf("execution = (%#v, %v), calls = %d", execution, err, builderCalls)
	}
}

func TestExecuteLocalGitChangeWithDebugOutputReviewLeavesUnsupportedOnlyReviewAbsent(t *testing.T) {
	adapter, baseRequest, headRequest := newContentMapLocalGitChangeFixture(t, map[string][]byte{}, map[string][]byte{"added.go": []byte("package sample\nfunc added() {}\n")})
	builderCalls := 0
	builder := func(change evidence.Change, contents map[string][]byte, limits review.DebugOutputChangeLimits) (review.DebugOutputChangeResult, error) {
		builderCalls++
		return review.DebugOutputChangeResult{}, errors.New("unexpected builder call")
	}
	execution, err := executeLocalGitChangeWithDebugOutputReview(context.Background(), baseRequest, headRequest, adapter, testDebugOutputReviewLimits(), executeLocalGitAcquisitionEnvelopeWithOwnedContent, evidence.ExecuteRepositoryFileDelta, builder)
	if err != nil || builderCalls != 0 || execution.HasReview() || execution.ChangeExecution().HasChange() || len(execution.ChangeExecution().EntryExecutions()) != 1 {
		t.Fatalf("execution = (%#v, %v), calls = %d", execution, err, builderCalls)
	}
}

func TestExecuteLocalGitChangeWithDebugOutputReviewRejectsLimitsBeforeAcquisition(t *testing.T) {
	adapter, baseRequest, headRequest := newSinglePathNamedLocalGitChangeFixture(t, "file.txt", []byte("old"), []byte("new"))
	endpointCalls, builderCalls := 0, 0
	endpoint := func(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, map[string][]byte, error) {
		endpointCalls++
		return executeLocalGitAcquisitionEnvelopeWithOwnedContent(ctx, request, adapter)
	}
	builder := func(change evidence.Change, contents map[string][]byte, limits review.DebugOutputChangeLimits) (review.DebugOutputChangeResult, error) {
		builderCalls++
		return review.DebugOutputChangeResult{}, nil
	}
	execution, err := executeLocalGitChangeWithDebugOutputReview(context.Background(), baseRequest, headRequest, adapter, review.DebugOutputChangeLimits{}, endpoint, evidence.ExecuteRepositoryFileDelta, builder)
	if !errors.Is(err, review.DebugOutputChangeResourceLimit) || endpointCalls != 0 || builderCalls != 0 || execution.Identity() != "" {
		t.Fatalf("execution = (%#v, %v), endpoint calls = %d, builder calls = %d", execution, err, endpointCalls, builderCalls)
	}
}

func TestExecuteLocalGitChangeWithDebugOutputReviewTransfersAllSupportedHeads(t *testing.T) {
	baseGo := []byte("package sample\nfunc target() {}\n")
	headGo := []byte("package sample\nimport \"fmt\"\nfunc target() { fmt.Println(\"debug\") }\n")
	base := map[string][]byte{"file.go": baseGo, "file.txt": []byte("old\n"), "removed.go": []byte("package sample\nfunc old() {}\n")}
	head := map[string][]byte{"added.go": []byte("package sample\nfunc added() {}\n"), "file.go": headGo, "file.txt": []byte("new\n")}
	adapter, baseRequest, headRequest := newContentMapLocalGitChangeFixture(t, base, head)
	limits := testDebugOutputReviewLimits()
	builderCalls := 0
	builder := func(change evidence.Change, contents map[string][]byte, supplied review.DebugOutputChangeLimits) (review.DebugOutputChangeResult, error) {
		builderCalls++
		if supplied != limits || len(contents) != 2 || !bytes.Equal(contents["file.go"], headGo) || !bytes.Equal(contents["file.txt"], head["file.txt"]) {
			return review.DebugOutputChangeResult{}, errors.New("unexpected retained head content")
		}
		return review.ReviewDebugOutputChange(change, contents, supplied)
	}
	execution, err := executeLocalGitChangeWithDebugOutputReview(context.Background(), baseRequest, headRequest, adapter, limits, executeLocalGitAcquisitionEnvelopeWithOwnedContent, evidence.ExecuteRepositoryFileDelta, builder)
	if err != nil || builderCalls != 1 || !execution.HasReview() || len(execution.Result().Files()) != 2 {
		t.Fatalf("execution = (%#v, %v), calls = %d", execution, err, builderCalls)
	}
	if _, ok := execution.Result().File("added.go"); ok {
		t.Fatal("unsupported added file appeared in review result")
	}
	if _, ok := execution.Result().File("removed.go"); ok {
		t.Fatal("unsupported removed file appeared in review result")
	}
}

func TestExecuteLocalGitChangeWithDebugOutputReviewClearsAliases(t *testing.T) {
	base := []byte("package sample\nfunc target() {}\n")
	head := []byte("package sample\nimport \"fmt\"\nfunc target() { fmt.Println(\"debug\") }\n")
	adapter, baseRequest, headRequest := newSinglePathNamedLocalGitChangeFixture(t, "file.go", base, head)
	limits := testDebugOutputReviewLimits()
	var acquiredAlias, builderAlias []byte
	var builderMap map[string][]byte
	calls := 0
	endpoint := func(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, map[string][]byte, error) {
		calls++
		envelope, manifest, contents, err := executeLocalGitAcquisitionEnvelopeWithOwnedContent(ctx, request, adapter)
		if calls == 2 && err == nil {
			acquiredAlias = contents["file.go"]
		}
		return envelope, manifest, contents, err
	}
	builder := func(change evidence.Change, contents map[string][]byte, supplied review.DebugOutputChangeLimits) (review.DebugOutputChangeResult, error) {
		builderMap = contents
		builderAlias = contents["file.go"]
		return review.ReviewDebugOutputChange(change, contents, supplied)
	}
	execution, err := executeLocalGitChangeWithDebugOutputReview(context.Background(), baseRequest, headRequest, adapter, limits, endpoint, evidence.ExecuteRepositoryFileDelta, builder)
	if err != nil || execution.Identity() == "" || len(acquiredAlias) == 0 || len(builderAlias) == 0 || len(builderMap) != 0 || !allZeroBytes(acquiredAlias) || !allZeroBytes(builderAlias) {
		t.Fatalf("execution = (%#v, %v), map=%#v acquired=%q builder=%q", execution, err, builderMap, acquiredAlias, builderAlias)
	}
}

func TestExecuteLocalGitChangeWithDebugOutputReviewClearsAfterBuilderMapMutationAndPanic(t *testing.T) {
	base := []byte("package sample\nfunc target() {}\n")
	head := []byte("package sample\nfunc target() { println(1) }\n")
	adapter, baseRequest, headRequest := newSinglePathNamedLocalGitChangeFixture(t, "file.go", base, head)
	var acquiredAlias, builderAlias []byte
	var builderMap map[string][]byte
	calls := 0
	endpoint := func(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, map[string][]byte, error) {
		calls++
		envelope, manifest, contents, err := executeLocalGitAcquisitionEnvelopeWithOwnedContent(ctx, request, adapter)
		if calls == 2 && err == nil {
			acquiredAlias = contents["file.go"]
		}
		return envelope, manifest, contents, err
	}
	builder := func(change evidence.Change, contents map[string][]byte, limits review.DebugOutputChangeLimits) (review.DebugOutputChangeResult, error) {
		builderMap = contents
		builderAlias = contents["file.go"]
		delete(contents, "file.go")
		panic("builder panic")
	}
	panicked := false
	func() {
		defer func() {
			panicked = recover() != nil
		}()
		_, _ = executeLocalGitChangeWithDebugOutputReview(context.Background(), baseRequest, headRequest, adapter, testDebugOutputReviewLimits(), endpoint, evidence.ExecuteRepositoryFileDelta, builder)
	}()
	if !panicked || len(acquiredAlias) == 0 || len(builderAlias) == 0 || len(builderMap) != 0 || !allZeroBytes(acquiredAlias) || !allZeroBytes(builderAlias) {
		t.Fatalf("panic cleanup failed: panicked=%v map=%#v acquired=%q builder=%q", panicked, builderMap, acquiredAlias, builderAlias)
	}
}

func TestExecuteLocalGitChangeWithDebugOutputReviewClearsOnBuilderError(t *testing.T) {
	base := []byte("package sample\nfunc target() {}\n")
	head := []byte("package sample\nfunc target() { println(1) }\n")
	adapter, baseRequest, headRequest := newSinglePathNamedLocalGitChangeFixture(t, "file.go", base, head)
	var alias []byte
	builderError := errors.New("builder failed")
	builder := func(change evidence.Change, contents map[string][]byte, limits review.DebugOutputChangeLimits) (review.DebugOutputChangeResult, error) {
		alias = contents["file.go"]
		return review.DebugOutputChangeResult{}, builderError
	}
	execution, err := executeLocalGitChangeWithDebugOutputReview(context.Background(), baseRequest, headRequest, adapter, testDebugOutputReviewLimits(), executeLocalGitAcquisitionEnvelopeWithOwnedContent, evidence.ExecuteRepositoryFileDelta, builder)
	if !errors.Is(err, builderError) || execution.Identity() != "" || len(alias) == 0 || !allZeroBytes(alias) {
		t.Fatalf("execution = (%#v, %v), alias=%q", execution, err, alias)
	}
}

func TestNewLocalGitDebugOutputReviewExecutionRejectsPartialOrMismatchedResults(t *testing.T) {
	adapter, baseRequest, headRequest := newSinglePathNamedLocalGitChangeFixture(t, "file.txt", []byte("old"), []byte("new"))
	execution, err := ExecuteLocalGitChangeWithDebugOutputReview(context.Background(), baseRequest, headRequest, adapter, testDebugOutputReviewLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name            string
		changeExecution LocalGitChangeExecution
		result          review.DebugOutputChangeResult
		hasReview       bool
	}{
		{name: "present without result", changeExecution: execution.ChangeExecution(), hasReview: true},
		{name: "absent with result", changeExecution: execution.ChangeExecution(), result: execution.Result()},
		{name: "result without Change", result: execution.Result(), hasReview: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := newLocalGitDebugOutputReviewExecution(test.changeExecution, test.result, test.hasReview)
			if err == nil || got.Identity() != "" {
				t.Fatalf("newLocalGitDebugOutputReviewExecution() = (%#v, %v)", got, err)
			}
		})
	}
}

func TestLocalGitDebugOutputReviewExecutionIsCompactAndIdentityBound(t *testing.T) {
	adapter, baseRequest, headRequest := newSinglePathNamedLocalGitChangeFixture(t, "file.txt", []byte("old"), []byte("new"))
	execution, err := ExecuteLocalGitChangeWithDebugOutputReview(context.Background(), baseRequest, headRequest, adapter, testDebugOutputReviewLimits())
	if err != nil || execution.Identity() == "" || execution.Identity() != expectedLocalGitDebugOutputReviewExecutionIdentity(execution) {
		t.Fatalf("execution = (%#v, %v)", execution, err)
	}
	assertGoImpactExecutionHasNoRawBytes(t, reflect.TypeOf(LocalGitDebugOutputReviewExecution{}), "LocalGitDebugOutputReviewExecution", map[reflect.Type]bool{})
	var zero LocalGitDebugOutputReviewExecution
	if zero.Identity() != "" || zero.ChangeExecution().Identity() != "" || zero.HasReview() || zero.Result().Identity() != "" {
		t.Fatalf("zero execution = %#v", zero)
	}
}

func testDebugOutputReviewLimits() review.DebugOutputChangeLimits {
	return review.DebugOutputChangeLimits{MaxFiles: 64, MaxBytesPerFile: 1 << 20, MaxTotalBytes: 64 << 20, MaxFindings: 1024}
}

func expectedLocalGitDebugOutputReviewExecutionIdentity(execution LocalGitDebugOutputReviewExecution) string {
	preimage := struct {
		Contract                string `json:"contract"`
		SchemaVersion           int    `json:"schema_version"`
		ChangeExecutionIdentity string `json:"change_execution_identity"`
		ReviewPresent           bool   `json:"review_present"`
		ReviewResultIdentity    string `json:"review_result_identity"`
	}{"open-trestle/local-git-debug-output-review-execution", 1, execution.ChangeExecution().Identity(), execution.HasReview(), execution.Result().Identity()}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
