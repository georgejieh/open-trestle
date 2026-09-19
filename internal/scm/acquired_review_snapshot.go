package scm

import (
	"fmt"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

// BindAcquiredReviewSnapshot binds review ranges to one verified local Git acquisition pair.
func BindAcquiredReviewSnapshot(
	workspace string,
	pair LocalGitAcquisitionPair,
	baseRequest evidence.RepositoryAcquisitionRequest,
	headRequest evidence.RepositoryAcquisitionRequest,
	ranges []evidence.SourceRange,
) (review.AcquiredReviewSnapshot, error) {
	if !pair.HasManifests() {
		return review.AcquiredReviewSnapshot{}, fmt.Errorf("local Git acquisition pair has no retained manifests")
	}
	pipelineSnapshot, err := review.NewAcquiredReviewPipelineSnapshot(workspace, pair.HeadManifest(), ranges)
	if err != nil {
		return review.AcquiredReviewSnapshot{}, err
	}
	return bindAcquiredReviewSnapshotFromPipeline(pipelineSnapshot, pair, baseRequest, headRequest)
}

func bindAcquiredReviewSnapshotFromPipeline(
	pipelineSnapshot review.ReviewSnapshot,
	pair LocalGitAcquisitionPair,
	baseRequest evidence.RepositoryAcquisitionRequest,
	headRequest evidence.RepositoryAcquisitionRequest,
) (review.AcquiredReviewSnapshot, error) {
	if !pair.HasManifests() {
		return review.AcquiredReviewSnapshot{}, fmt.Errorf("local Git acquisition pair has no retained manifests")
	}
	if err := evidence.ValidateRepositoryAcquisitionRequest(baseRequest); err != nil {
		return review.AcquiredReviewSnapshot{}, fmt.Errorf("base repository acquisition request: %w", err)
	}
	if err := evidence.ValidateRepositoryAcquisitionRequest(headRequest); err != nil {
		return review.AcquiredReviewSnapshot{}, fmt.Errorf("head repository acquisition request: %w", err)
	}
	baseBinding := pair.BaseEnvelope().EvidenceBinding()
	headBinding := pair.HeadEnvelope().EvidenceBinding()
	matchingBase := baseBinding.RequestIdentity() == baseRequest.Identity()
	matchingHead := headBinding.RequestIdentity() == headRequest.Identity()
	matchingRepository := baseRequest.RepositoryIdentity() == headRequest.RepositoryIdentity()
	matchingPairRepository := baseBinding.RepositoryIdentity() == baseRequest.RepositoryIdentity() && headBinding.RepositoryIdentity() == headRequest.RepositoryIdentity()
	if !matchingBase || !matchingHead || !matchingRepository || !matchingPairRepository {
		return review.AcquiredReviewSnapshot{}, fmt.Errorf("acquisition requests do not match local Git pair")
	}
	return review.NewAcquiredReviewSnapshot(
		pipelineSnapshot,
		headRequest.Repository(),
		baseRequest.Revision(),
		headRequest.Revision(),
		baseBinding,
		headBinding,
		pair.BaseManifest(),
		pair.HeadManifest(),
		pair.ManifestDelta(),
	)
}
