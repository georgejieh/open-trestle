package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

type localGitDebugOutputReviewBuilder func(evidence.Change, map[string][]byte, review.DebugOutputChangeLimits) (review.DebugOutputChangeResult, error)

// LocalGitDebugOutputReviewExecution binds one change execution to detached debug-output review evidence.
type LocalGitDebugOutputReviewExecution struct {
	identity        string
	changeExecution LocalGitChangeExecution
	hasReview       bool
	result          review.DebugOutputChangeResult
}

// ExecuteLocalGitChangeWithDebugOutputReview derives static findings while head bytes remain in scope.
func ExecuteLocalGitChangeWithDebugOutputReview(ctx context.Context, baseRequest, headRequest evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter, limits review.DebugOutputChangeLimits) (LocalGitDebugOutputReviewExecution, error) {
	return executeLocalGitChangeWithDebugOutputReview(ctx, baseRequest, headRequest, adapter, limits, executeLocalGitAcquisitionEnvelopeWithOwnedContent, evidence.ExecuteRepositoryFileDelta, review.ReviewDebugOutputChange)
}

func executeLocalGitChangeWithDebugOutputReview(ctx context.Context, baseRequest, headRequest evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter, limits review.DebugOutputChangeLimits, endpoint localGitChangeEndpoint, fileExecutor localGitFileDeltaExecutor, builder localGitDebugOutputReviewBuilder) (LocalGitDebugOutputReviewExecution, error) {
	if builder == nil {
		return LocalGitDebugOutputReviewExecution{}, fmt.Errorf("debug-output review builder is nil")
	}
	if err := review.ValidateDebugOutputChangeLimits(limits); err != nil {
		return LocalGitDebugOutputReviewExecution{}, err
	}
	changeExecution, retainedHeadContents, err := executeLocalGitChangeRetainingHead(ctx, baseRequest, headRequest, adapter, endpoint, fileExecutor, localGitHeadRetentionAll)
	if err != nil {
		return LocalGitDebugOutputReviewExecution{}, err
	}
	defer clearLocalGitRetainedHeadContents(retainedHeadContents)
	if !changeExecution.HasChange() {
		return newLocalGitDebugOutputReviewExecution(changeExecution, review.DebugOutputChangeResult{}, false)
	}
	builderContents := cloneLocalGitRetainedHeadContents(retainedHeadContents)
	defer clearLocalGitRetainedHeadContents(builderContents)
	result, err := builder(changeExecution.Change(), builderContents, limits)
	clearLocalGitRetainedHeadContents(builderContents)
	builderContents = nil
	clearLocalGitRetainedHeadContents(retainedHeadContents)
	retainedHeadContents = nil
	if err != nil {
		return LocalGitDebugOutputReviewExecution{}, err
	}
	if err := ctx.Err(); err != nil {
		return LocalGitDebugOutputReviewExecution{}, err
	}
	return newLocalGitDebugOutputReviewExecution(changeExecution, result, true)
}

func cloneLocalGitRetainedHeadContents(contents map[string][]byte) map[string][]byte {
	if len(contents) == 0 {
		return nil
	}
	cloned := make(map[string][]byte, len(contents))
	for path, content := range contents {
		cloned[path] = content
	}
	return cloned
}

func newLocalGitDebugOutputReviewExecution(changeExecution LocalGitChangeExecution, result review.DebugOutputChangeResult, hasReview bool) (LocalGitDebugOutputReviewExecution, error) {
	canonicalChangeExecution, err := newLocalGitChangeExecution(changeExecution.AcquisitionPair(), changeExecution.Change(), changeExecution.HasChange(), changeExecution.EntryExecutions())
	if err != nil || canonicalChangeExecution.Identity() != changeExecution.Identity() {
		return LocalGitDebugOutputReviewExecution{}, fmt.Errorf("local Git change execution is not canonical")
	}
	resultIdentity := ""
	if hasReview {
		if !changeExecution.HasChange() || result.Identity() == "" || result.ChangeIdentity() != changeExecution.Change().Identity() {
			return LocalGitDebugOutputReviewExecution{}, fmt.Errorf("debug-output review result does not match change execution")
		}
		resultIdentity = result.Identity()
	} else if changeExecution.HasChange() || result.Identity() != "" {
		return LocalGitDebugOutputReviewExecution{}, fmt.Errorf("absent debug-output review result must be zero")
	}
	preimage := struct {
		Contract                string `json:"contract"`
		SchemaVersion           int    `json:"schema_version"`
		ChangeExecutionIdentity string `json:"change_execution_identity"`
		ReviewPresent           bool   `json:"review_present"`
		ReviewResultIdentity    string `json:"review_result_identity"`
	}{
		Contract:                "open-trestle/local-git-debug-output-review-execution",
		SchemaVersion:           1,
		ChangeExecutionIdentity: changeExecution.Identity(),
		ReviewPresent:           hasReview,
		ReviewResultIdentity:    resultIdentity,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return LocalGitDebugOutputReviewExecution{}, err
	}
	digest := sha256.Sum256(encoded)
	return LocalGitDebugOutputReviewExecution{
		identity: hex.EncodeToString(digest[:]), changeExecution: changeExecution,
		hasReview: hasReview, result: result,
	}, nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (e LocalGitDebugOutputReviewExecution) Identity() string { return e.identity }

// ChangeExecution returns the exact owning local Git change execution.
func (e LocalGitDebugOutputReviewExecution) ChangeExecution() LocalGitChangeExecution {
	return e.changeExecution
}

// HasReview reports whether a supported Change produced debug-output review evidence.
func (e LocalGitDebugOutputReviewExecution) HasReview() bool { return e.hasReview }

// Result returns the detached change-level debug-output review result.
func (e LocalGitDebugOutputReviewExecution) Result() review.DebugOutputChangeResult { return e.result }
