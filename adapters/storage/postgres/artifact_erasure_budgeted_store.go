package postgres

import (
	"context"

	"github.com/georgejieh/open-trestle/adapters/storage/s3"
	"github.com/georgejieh/open-trestle/artifact"
)

// BudgetedEnvelopeDependencies binds the owned backend to one verified index.
type BudgetedEnvelopeDependencies struct {
	Backend        *s3.ErasureBackend
	Keys           artifact.EnvelopeKeyProvider
	Clock          artifact.ErasureClock
	IndexAuthority VerifiedBudgetedErasureIndex
}

// NewIndexedBudgetedEnvelopeStore composes explicit budgeted erasure mode without I/O.
func NewIndexedBudgetedEnvelopeStore(index *ArtifactIndex, deps BudgetedEnvelopeDependencies, policy artifact.ProtectedErasurePolicy) (*IndexedArtifactStore, error) {
	resumeJournal, err := newArtifactResumeJournal(index, deps.IndexAuthority, policy, deps.Clock)
	if err != nil {
		return nil, err
	}
	envelope, err := artifact.NewEnvelopeStoreWithErasure(artifact.EnvelopeErasureOptions{
		Backend: deps.Backend, Keys: deps.Keys, Journal: resumeJournal, Policy: policy, Clock: deps.Clock,
	})
	if err != nil {
		return nil, err
	}
	return &IndexedArtifactStore{
		index: index, artifacts: envelope, admission: envelope,
		journal: resumeJournal.artifactAdmissionJournal, resume: envelope,
	}, nil
}

// ResumeErasure forwards only for explicitly composed budgeted-mode instances.
func (s *IndexedArtifactStore) ResumeErasure(ctx context.Context, ref artifact.ErasureOperationRef, allowance artifact.ResumeAllowance) (artifact.ErasureResult, error) {
	if s == nil || s.resume == nil {
		return artifact.ErasureResult{}, artifact.ErrErasureJournalRequired
	}
	return s.resume.ResumeErasure(ctx, ref, allowance)
}

// ReadErasure forwards immutable readback only for budgeted-mode instances.
func (s *IndexedArtifactStore) ReadErasure(ctx context.Context, ref artifact.ErasureOperationRef) (artifact.ErasureResult, bool, error) {
	if s == nil || s.resume == nil {
		return artifact.ErasureResult{}, false, artifact.ErrErasureJournalRequired
	}
	return s.resume.ReadErasure(ctx, ref)
}

var _ artifact.BudgetedErasureStore = (*IndexedArtifactStore)(nil)
