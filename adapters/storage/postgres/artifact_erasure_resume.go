package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/georgejieh/open-trestle/artifact"
)

type VerifiedBudgetedErasureIndex struct {
	base                   VerifiedErasureIndex
	resumeDescriptorDigest string
}

func (VerifiedBudgetedErasureIndex) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("verified budgeted erasure index{redacted}"))
}
func (VerifiedBudgetedErasureIndex) String() string {
	return "verified budgeted erasure index{redacted}"
}
func (VerifiedBudgetedErasureIndex) GoString() string {
	return "verified budgeted erasure index{redacted}"
}
func (w VerifiedBudgetedErasureIndex) matches(index *ArtifactIndex) bool {
	return w.base.matches(index) && w.resumeDescriptorDigest == resumeSchemaDescriptorDigest()
}

// VerifyBudgetedErasureIndex requires the normal thirteen-migration registry.
func VerifyBudgetedErasureIndex(ctx context.Context, index *ArtifactIndex) (VerifiedBudgetedErasureIndex, error) {
	if err := validateArtifactIndex(ctx, index); err != nil {
		return VerifiedBudgetedErasureIndex{}, err
	}
	tx, err := index.store.database.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return VerifiedBudgetedErasureIndex{}, artifact.ErrErasureJournalUnavailable
	}
	defer tx.Rollback()
	if err := verifyDatabaseAuthoritySchemas(ctx, tx); err != nil {
		return VerifiedBudgetedErasureIndex{}, err
	}
	if err := verifyMigrationsTransaction(ctx, tx); err != nil {
		return VerifiedBudgetedErasureIndex{}, err
	}
	authority, err := readDatabaseAuthority(ctx, tx)
	if err != nil {
		return VerifiedBudgetedErasureIndex{}, err
	}
	if err := verifyArtifactErasureSchema(ctx, tx, authority.schemaName, authority.roleName); err != nil {
		return VerifiedBudgetedErasureIndex{}, erasurePublicError(err)
	}
	if err := verifyResumeSchema(ctx, tx, authority.schemaName, authority.roleName); err != nil {
		return VerifiedBudgetedErasureIndex{}, erasurePublicError(err)
	}
	if err := tx.Commit(); err != nil {
		return VerifiedBudgetedErasureIndex{}, artifact.ErrErasureJournalUnavailable
	}
	return VerifiedBudgetedErasureIndex{base: VerifiedErasureIndex{index: index, database: index.store.database, authority: authority, descriptorDigest: erasureSchemaDescriptorDigest()}, resumeDescriptorDigest: resumeSchemaDescriptorDigest()}, nil
}

type artifactResumeJournal struct {
	*artifactAdmissionJournal
	budgetedAuthority VerifiedBudgetedErasureIndex
}

func newArtifactResumeJournal(index *ArtifactIndex, w VerifiedBudgetedErasureIndex, policy artifact.ProtectedErasurePolicy, clock artifact.ErasureClock) (*artifactResumeJournal, error) {
	if !w.matches(index) {
		return nil, ErrDatabaseAuthorityMismatch
	}
	base, err := newArtifactAdmissionJournal(index, w.base, policy, clock)
	if err != nil {
		return nil, err
	}
	return &artifactResumeJournal{artifactAdmissionJournal: base, budgetedAuthority: w}, nil
}
func (artifactResumeJournal) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("artifact resume journal{redacted}"))
}
func (j *artifactResumeJournal) validateResume(ctx context.Context, ref artifact.ErasureOperationRef) error {
	if j == nil || j.artifactAdmissionJournal == nil || !j.budgetedAuthority.matches(j.index) {
		return artifact.ErrErasureJournalUnavailable
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	return j.validate(ctx, ref.Scope(), ref.NamespaceIdentity(), ref.OperationIdentity())
}

var _ artifact.ResumeJournal = (*artifactResumeJournal)(nil)
