package scm

import (
	"context"
	"errors"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// ErrInvalidMergeBaseRequest identifies a malformed or cross-wired merge-base request.
var ErrInvalidMergeBaseRequest = errors.New("invalid merge base request")

// MergeBaseOutcome classifies one merge-base resolution.
type MergeBaseOutcome uint8

const (
	// MergeBaseResolved reports the forge's merge base of the two commits.
	MergeBaseResolved MergeBaseOutcome = iota + 1
	// MergeBaseNone reports that both commits exist and share no history.
	MergeBaseNone
	// MergeBaseUnavailable reports that no merge base could be read; Reason
	// classifies why, with the acquisition vocabulary.
	MergeBaseUnavailable
)

// MergeBaseRequest asks one adapter for the merge base of two exact commits.
type MergeBaseRequest struct {
	repository evidence.RepositoryIdentity
	base, head evidence.RevisionIdentity
	adapter    evidence.SourceAdapterIdentity
}

// NewMergeBaseRequest validates a read-only merge-base request for two commits
// of the same object algorithm.
func NewMergeBaseRequest(repository evidence.RepositoryIdentity, base, head evidence.RevisionIdentity, adapter evidence.SourceAdapterIdentity) (MergeBaseRequest, error) {
	canonicalRepository, repositoryErr := evidence.NewRepositoryIdentity(repository.Authority(), repository.Namespace(), repository.Name())
	canonicalBase, baseErr := evidence.NewRevisionIdentity(base.Kind(), base.Algorithm(), base.Digest())
	canonicalHead, headErr := evidence.NewRevisionIdentity(head.Kind(), head.Algorithm(), head.Digest())
	canonicalAdapter, adapterErr := evidence.NewSourceAdapterIdentity(adapter.Kind(), adapter.Name(), adapter.Version(), adapter.Capabilities())
	if repositoryErr != nil || baseErr != nil || headErr != nil || adapterErr != nil || canonicalRepository.Identity() != repository.Identity() || canonicalBase != base || canonicalHead != head || canonicalAdapter.Identity() != adapter.Identity() ||
		base.Kind() != evidence.RevisionKindGitCommit || head.Kind() != evidence.RevisionKindGitCommit || base.Algorithm() != head.Algorithm() {
		return MergeBaseRequest{}, ErrInvalidMergeBaseRequest
	}
	return MergeBaseRequest{repository: repository, base: base, head: head, adapter: canonicalAdapter}, nil
}

func (r MergeBaseRequest) Repository() evidence.RepositoryIdentity { return r.repository }
func (r MergeBaseRequest) Base() evidence.RevisionIdentity         { return r.base }
func (r MergeBaseRequest) Head() evidence.RevisionIdentity         { return r.head }
func (r MergeBaseRequest) Adapter() evidence.SourceAdapterIdentity { return r.adapter }

// MergeBaseResult carries one typed resolution. MergeBase is set only when
// resolved; Reason is set only when unavailable.
type MergeBaseResult struct {
	Outcome   MergeBaseOutcome
	MergeBase evidence.RevisionIdentity
	Reason    evidence.RepositoryAcquisitionReason
}

// MergeBaseResolver reports the forge's merge base of two exact commits
// without writing repository state.
type MergeBaseResolver interface {
	ResolveMergeBase(context.Context, MergeBaseRequest) MergeBaseResult
}

// ValidateMergeBaseResult accepts a result only when it is closed for the request.
func ValidateMergeBaseResult(request MergeBaseRequest, result MergeBaseResult) error {
	switch result.Outcome {
	case MergeBaseResolved:
		canonical, err := evidence.NewRevisionIdentity(result.MergeBase.Kind(), result.MergeBase.Algorithm(), result.MergeBase.Digest())
		if err != nil || canonical != result.MergeBase || canonical.Kind() != evidence.RevisionKindGitCommit || canonical.Algorithm() != request.base.Algorithm() || result.Reason != evidence.AcquisitionReasonNone {
			return ErrInvalidMergeBaseRequest
		}
	case MergeBaseNone:
		if result.MergeBase != (evidence.RevisionIdentity{}) || result.Reason != evidence.AcquisitionReasonNone {
			return ErrInvalidMergeBaseRequest
		}
	case MergeBaseUnavailable:
		if result.MergeBase != (evidence.RevisionIdentity{}) || result.Reason == evidence.AcquisitionReasonNone || result.Reason == "" {
			return ErrInvalidMergeBaseRequest
		}
	default:
		return ErrInvalidMergeBaseRequest
	}
	return nil
}
