package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

var (
	// ErrArtifactMetadataNotFound identifies an artifact absent from the canonical metadata index.
	ErrArtifactMetadataNotFound = errors.New("artifact metadata not found")
	// ErrArtifactIndexConflict identifies immutable metadata with the same scoped key but different content.
	ErrArtifactIndexConflict = errors.New("artifact metadata conflict")
)

// ArtifactMetadata is a payload-free canonical storage index entry.
type ArtifactMetadata struct {
	scope                           audit.ReviewScope
	artifactIdentity, payloadDigest string
	kind                            artifact.Kind
	classification                  artifact.Classification
	origin                          artifact.Origin
	protection                      artifact.Protection
	createdAt, expiresAt            time.Time
}

func newArtifactMetadata(value artifact.Artifact) (ArtifactMetadata, error) {
	if value.Validate() != nil {
		return ArtifactMetadata{}, artifact.ErrInvalidArtifact
	}
	return ArtifactMetadata{
		scope: value.Scope(), artifactIdentity: value.Identity(), payloadDigest: value.PayloadDigest(),
		kind: value.Kind(), classification: value.Classification(), origin: value.Origin(), protection: value.Protection(),
		createdAt: value.CreatedAt(), expiresAt: value.ExpiresAt(),
	}, nil
}
func (m ArtifactMetadata) Scope() audit.ReviewScope                { return m.scope }
func (m ArtifactMetadata) ArtifactIdentity() string                { return m.artifactIdentity }
func (m ArtifactMetadata) PayloadDigest() string                   { return m.payloadDigest }
func (m ArtifactMetadata) Kind() artifact.Kind                     { return m.kind }
func (m ArtifactMetadata) Classification() artifact.Classification { return m.classification }
func (m ArtifactMetadata) Origin() artifact.Origin                 { return m.origin }
func (m ArtifactMetadata) Protection() artifact.Protection         { return m.protection }
func (m ArtifactMetadata) CreatedAt() time.Time                    { return m.createdAt }
func (m ArtifactMetadata) ExpiresAt() time.Time                    { return m.expiresAt }
func (m ArtifactMetadata) String() string                          { return "artifact metadata" }
func (m ArtifactMetadata) GoString() string                        { return "postgres.ArtifactMetadata{<redacted>}" }
func (m ArtifactMetadata) Format(state fmt.State, verb rune) {
	writePostgresRedacted(state, verb, "artifact metadata", "postgres.ArtifactMetadata{<redacted>}")
}

// Validate checks bounded payload-free metadata fields.
func (m ArtifactMetadata) Validate() error {
	validIdentity := validDigest(m.artifactIdentity) && validDigest(m.payloadDigest)
	validEnums := m.kind.String() != "" && m.classification.String() != "" && m.origin.String() != "" && m.protection.String() != ""
	if m.scope.Validate() != nil || !validIdentity || !validEnums || m.createdAt.IsZero() || !m.expiresAt.After(m.createdAt) {
		return ErrCorruptRecord
	}
	return nil
}
func (m ArtifactMetadata) matches(value artifact.Artifact) bool {
	validIdentity := value.Validate() == nil && m.scope.Identity() == value.Scope().Identity() && m.artifactIdentity == value.Identity() && m.payloadDigest == value.PayloadDigest()
	validType := m.kind == value.Kind() && m.classification == value.Classification() && m.origin == value.Origin() && m.protection == value.Protection()
	validTime := m.createdAt.Equal(value.CreatedAt()) && m.expiresAt.Equal(value.ExpiresAt())
	return validIdentity && validType && validTime
}

// ArtifactIndex stores payload-free artifact and deletion lineage.
type ArtifactIndex struct{ store *Store }

// NewArtifactIndex validates a database handle without applying migrations.
func NewArtifactIndex(database *sql.DB) (*ArtifactIndex, error) {
	store, err := New(database)
	if err != nil {
		return nil, err
	}
	return &ArtifactIndex{store: store}, nil
}

// RegisterArtifact inserts exact immutable artifact metadata idempotently.
func (i *ArtifactIndex) RegisterArtifact(ctx context.Context, value artifact.Artifact) (bool, error) {
	if err := validateArtifactIndex(ctx, i); err != nil {
		return false, err
	}
	metadata, err := newArtifactMetadata(value)
	if err != nil {
		return false, err
	}
	inserted := false
	err = i.store.retrySerializableMutation(ctx, metadata.scope.TenantID(), ErrDatabaseUnavailable, func(tx *sql.Tx) error {
		inserted = false
		if err := lockScopeTransaction(ctx, tx, "artifact:"+metadata.scope.Identity()+":"+metadata.artifactIdentity); err != nil {
			return err
		}
		if err := ensureScopeTransaction(ctx, tx, metadata.scope); err != nil {
			return err
		}
		existing, found, err := queryArtifactMetadataTransaction(ctx, tx, metadata.scope, metadata.artifactIdentity)
		if err != nil {
			return err
		}
		if found {
			if !existing.matches(value) {
				return ErrArtifactIndexConflict
			}
			return nil
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO open_trestle_artifacts
(tenant_id, repository_id, review_run_id, scope_identity, artifact_identity, payload_digest, kind, classification, origin, protection, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			metadata.scope.TenantID(), metadata.scope.RepositoryID(), metadata.scope.ReviewRunID(),
			metadata.scope.Identity(), metadata.artifactIdentity, metadata.payloadDigest,
			metadata.kind.String(), metadata.classification.String(), metadata.origin.String(),
			metadata.protection.String(), metadata.createdAt, metadata.expiresAt,
		); err != nil {
			return classifyTransactionError(err)
		}
		inserted = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// GetArtifactMetadata reads and validates one exact scoped metadata entry.
func (i *ArtifactIndex) GetArtifactMetadata(ctx context.Context, scope audit.ReviewScope, identity string) (ArtifactMetadata, error) {
	if err := validateArtifactIndex(ctx, i); err != nil {
		return ArtifactMetadata{}, err
	}
	if scope.Validate() != nil || !validDigest(identity) {
		return ArtifactMetadata{}, ErrArtifactMetadataNotFound
	}
	tx, err := i.store.beginTenant(ctx, scope.TenantID(), sql.LevelReadCommitted)
	if err != nil {
		return ArtifactMetadata{}, err
	}
	defer tx.Rollback()
	metadata, found, err := queryArtifactMetadata(ctx, tx, scope, identity)
	if err != nil {
		return ArtifactMetadata{}, err
	}
	if !found {
		return ArtifactMetadata{}, ErrArtifactMetadataNotFound
	}
	if err := commit(tx); err != nil {
		return ArtifactMetadata{}, err
	}
	return metadata, nil
}

func queryArtifactMetadata(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope, identity string) (ArtifactMetadata, bool, error) {
	metadata, found, err := queryArtifactMetadataTransaction(ctx, tx, scope, identity)
	return metadata, found, redactTransactionError(err)
}

func queryArtifactMetadataTransaction(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope, identity string) (ArtifactMetadata, bool, error) {
	var payloadDigest, kind, classification, origin, protection string
	var createdAt, expiresAt time.Time
	err := tx.QueryRowContext(
		ctx,
		`SELECT payload_digest, kind, classification, origin, protection, created_at, expires_at
FROM open_trestle_artifacts
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4`,
		scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), identity,
	).Scan(&payloadDigest, &kind, &classification, &origin, &protection, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ArtifactMetadata{}, false, nil
	}
	if err != nil {
		return ArtifactMetadata{}, false, classifyTransactionError(err)
	}
	metadata := ArtifactMetadata{
		scope: scope, artifactIdentity: identity, payloadDigest: payloadDigest,
		kind: parseArtifactKind(kind), classification: parseArtifactClassification(classification),
		origin: parseArtifactOrigin(origin), protection: parseArtifactProtection(protection),
		createdAt: createdAt, expiresAt: expiresAt,
	}
	if metadata.Validate() != nil {
		return ArtifactMetadata{}, false, ErrCorruptRecord
	}
	return metadata, true, nil
}

// RecordDeletionAuthorization stores policy and legal-hold authority before physical deletion.
func (i *ArtifactIndex) RecordDeletionAuthorization(ctx context.Context, authorization artifact.DeletionAuthorization) (bool, error) {
	if err := validateArtifactIndex(ctx, i); err != nil {
		return false, err
	}
	if authorization.Validate() != nil {
		return false, artifact.ErrInvalidDeletionAuthorization
	}
	scope := authorization.Scope()
	inserted := false
	err := i.store.retrySerializableMutation(ctx, scope.TenantID(), ErrDatabaseUnavailable, func(tx *sql.Tx) error {
		inserted = false
		if err := lockScopeTransaction(ctx, tx, "artifact-auth:"+authorization.Identity()); err != nil {
			return err
		}
		if _, found, err := queryArtifactMetadataTransaction(ctx, tx, scope, authorization.ArtifactIdentity()); err != nil {
			return err
		} else if !found {
			return ErrArtifactMetadataNotFound
		}
		var existingIdentity, artifactIdentity, policyIdentity, principalIdentity, holdIdentity, reason string
		var issuedAt, expiresAt time.Time
		err := tx.QueryRowContext(
			ctx,
			`SELECT authorization_identity, artifact_identity, policy_identity, principal_identity, hold_clearance_identity, reason, issued_at, expires_at
FROM open_trestle_artifact_deletion_authorizations
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND authorization_identity = $4`,
			scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), authorization.Identity(),
		).Scan(
			&existingIdentity, &artifactIdentity, &policyIdentity, &principalIdentity,
			&holdIdentity, &reason, &issuedAt, &expiresAt,
		)
		if err == nil {
			validIdentity := existingIdentity == authorization.Identity() && artifactIdentity == authorization.ArtifactIdentity()
			validAuthority := policyIdentity == authorization.PolicyIdentity() && principalIdentity == authorization.PrincipalIdentity() && holdIdentity == authorization.HoldClearanceIdentity()
			validPolicy := reason == authorization.Reason().String() && issuedAt.Equal(authorization.IssuedAt()) && expiresAt.Equal(authorization.ExpiresAt())
			matches := validIdentity && validAuthority && validPolicy
			if !matches {
				return ErrArtifactIndexConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return classifyTransactionError(err)
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO open_trestle_artifact_deletion_authorizations
(tenant_id, repository_id, review_run_id, scope_identity, authorization_identity, artifact_identity, policy_identity, principal_identity, hold_clearance_identity, reason, issued_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(),
			authorization.Identity(), authorization.ArtifactIdentity(), authorization.PolicyIdentity(),
			authorization.PrincipalIdentity(), authorization.HoldClearanceIdentity(), authorization.Reason().String(),
			authorization.IssuedAt(), authorization.ExpiresAt(),
		); err != nil {
			return classifyTransactionError(err)
		}
		inserted = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// RecordDeletionReceipt stores content-free completion evidence after physical deletion.
func (i *ArtifactIndex) RecordDeletionReceipt(ctx context.Context, receipt artifact.DeletionReceipt) (bool, error) {
	if err := validateArtifactIndex(ctx, i); err != nil {
		return false, err
	}
	if receipt.Validate() != nil {
		return false, artifact.ErrInvalidDeletionReceipt
	}
	scope := receipt.Scope()
	inserted := false
	err := i.store.retrySerializableMutation(ctx, scope.TenantID(), ErrDatabaseUnavailable, func(tx *sql.Tx) error {
		inserted = false
		if err := lockScopeTransaction(ctx, tx, "artifact-delete:"+receipt.ArtifactIdentity()); err != nil {
			return err
		}
		metadata, found, err := queryArtifactMetadataTransaction(ctx, tx, scope, receipt.ArtifactIdentity())
		if err != nil {
			return err
		}
		if !found {
			return ErrArtifactMetadataNotFound
		}
		if metadata.PayloadDigest() != receipt.PayloadDigest() {
			return ErrArtifactIndexConflict
		}
		var authorizedArtifact string
		err = tx.QueryRowContext(
			ctx,
			`SELECT artifact_identity
FROM open_trestle_artifact_deletion_authorizations
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND authorization_identity = $4`,
			scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), receipt.AuthorizationIdentity(),
		).Scan(&authorizedArtifact)
		if errors.Is(err, sql.ErrNoRows) {
			return artifact.ErrDeletionNotAllowed
		}
		if err != nil {
			return classifyTransactionError(err)
		}
		if authorizedArtifact != receipt.ArtifactIdentity() {
			return ErrArtifactIndexConflict
		}
		var existingIdentity, existingPayload, existingAuthorization string
		var existingDeletedAt time.Time
		err = tx.QueryRowContext(
			ctx,
			`SELECT receipt_identity, payload_digest, authorization_identity, deleted_at
FROM open_trestle_artifact_deletion_receipts
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND artifact_identity = $4`,
			scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), receipt.ArtifactIdentity(),
		).Scan(&existingIdentity, &existingPayload, &existingAuthorization, &existingDeletedAt)
		if err == nil {
			validIdentity := existingIdentity == receipt.Identity() && existingPayload == receipt.PayloadDigest()
			matches := validIdentity && existingAuthorization == receipt.AuthorizationIdentity() && existingDeletedAt.Equal(receipt.DeletedAt())
			if !matches {
				return ErrArtifactIndexConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return classifyTransactionError(err)
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO open_trestle_artifact_deletion_receipts
(tenant_id, repository_id, review_run_id, scope_identity, receipt_identity, artifact_identity, payload_digest, authorization_identity, deleted_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(),
			receipt.Identity(), receipt.ArtifactIdentity(), receipt.PayloadDigest(),
			receipt.AuthorizationIdentity(), receipt.DeletedAt(),
		); err != nil {
			return classifyTransactionError(err)
		}
		inserted = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// ListExpiredArtifacts returns undeleted metadata in stable expiry and identity order.
func (i *ArtifactIndex) ListExpiredArtifacts(
	ctx context.Context,
	tenantID, repositoryID string,
	cutoff time.Time,
	afterExpiry time.Time,
	afterIdentity string,
	limit int,
) ([]ArtifactMetadata, error) {
	if err := validateArtifactIndex(ctx, i); err != nil {
		return nil, err
	}
	validCursor := afterExpiry.IsZero() && afterIdentity == "" || !afterExpiry.IsZero() && validDigest(afterIdentity)
	if !validScopeValue(tenantID) || !validScopeValue(repositoryID) || cutoff.IsZero() || !validCursor || limit <= 0 || limit > 1000 {
		return nil, ErrInvalidDatabase
	}
	if afterExpiry.IsZero() {
		afterExpiry = time.UnixMilli(1)
	}
	tx, err := i.store.beginTenant(ctx, tenantID, sql.LevelReadCommitted)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT review_run_id, scope_identity, artifact_identity, payload_digest, kind, classification, origin, protection, created_at, expires_at
FROM open_trestle_artifacts AS artifact
WHERE tenant_id = $1 AND repository_id = $2 AND expires_at <= $3
  AND (expires_at, artifact_identity) > ($4, $5)
  AND NOT EXISTS (
    SELECT 1 FROM open_trestle_artifact_deletion_receipts AS receipt
    WHERE receipt.tenant_id = artifact.tenant_id
      AND receipt.repository_id = artifact.repository_id
      AND receipt.review_run_id = artifact.review_run_id
      AND receipt.artifact_identity = artifact.artifact_identity
  )
ORDER BY expires_at ASC, artifact_identity ASC LIMIT $6`, tenantID, repositoryID, cutoff.UTC(), afterExpiry.UTC(), afterIdentity, limit)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer rows.Close()
	result := make([]ArtifactMetadata, 0)
	previousExpiry, previousIdentity := afterExpiry, afterIdentity
	for rows.Next() {
		var runID, scopeIdentity, artifactIdentity, payloadDigest string
		var kind, classification, origin, protection string
		var createdAt, expiresAt time.Time
		if err := rows.Scan(&runID, &scopeIdentity, &artifactIdentity, &payloadDigest, &kind, &classification, &origin, &protection, &createdAt, &expiresAt); err != nil {
			return nil, ErrDatabaseUnavailable
		}
		scope, scopeErr := audit.NewReviewScope(tenantID, repositoryID, runID)
		metadata := ArtifactMetadata{
			scope: scope, artifactIdentity: artifactIdentity, payloadDigest: payloadDigest,
			kind: parseArtifactKind(kind), classification: parseArtifactClassification(classification),
			origin: parseArtifactOrigin(origin), protection: parseArtifactProtection(protection),
			createdAt: createdAt, expiresAt: expiresAt,
		}
		ordered := expiresAt.After(previousExpiry) || expiresAt.Equal(previousExpiry) && artifactIdentity > previousIdentity
		if scopeErr != nil || scope.Identity() != scopeIdentity || metadata.Validate() != nil || expiresAt.After(cutoff) || !ordered {
			return nil, ErrCorruptRecord
		}
		result = append(result, metadata)
		previousExpiry, previousIdentity = expiresAt, artifactIdentity
	}
	if rows.Err() != nil {
		return nil, ErrDatabaseUnavailable
	}
	if err := rows.Close(); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	if err := commit(tx); err != nil {
		return nil, err
	}
	return result, nil
}

func validateArtifactIndex(ctx context.Context, index *ArtifactIndex) error {
	if nilContext(ctx) || index == nil || index.store == nil || index.store.database == nil {
		return ErrInvalidDatabase
	}
	if ctx.Err() != nil {
		return ErrDatabaseUnavailable
	}
	return nil
}
func parseArtifactKind(value string) artifact.Kind {
	for candidate := artifact.KindSourceSnapshot; candidate <= artifact.KindInvestigationToolResult; candidate++ {
		if candidate.String() == value {
			return candidate
		}
	}
	return 0
}
func parseArtifactClassification(value string) artifact.Classification {
	for candidate := artifact.ClassificationPublic; candidate <= artifact.ClassificationRestricted; candidate++ {
		if candidate.String() == value {
			return candidate
		}
	}
	return 0
}
func parseArtifactOrigin(value string) artifact.Origin {
	for candidate := artifact.OriginHost; candidate <= artifact.OriginMemory; candidate++ {
		if candidate.String() == value {
			return candidate
		}
	}
	return 0
}
func parseArtifactProtection(value string) artifact.Protection {
	for candidate := artifact.ProtectionProcessPrivate; candidate <= artifact.ProtectionEnvelopeEncrypted; candidate++ {
		if candidate.String() == value {
			return candidate
		}
	}
	return 0
}
func writePostgresRedacted(state fmt.State, verb rune, plain, syntax string) {
	value := plain
	if verb == 'q' {
		value = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		value = syntax
	}
	_, _ = state.Write([]byte(value))
}

// IndexedArtifactStore keeps physical storage and canonical metadata recoverably aligned.
type IndexedArtifactStore struct {
	index     *ArtifactIndex
	artifacts artifact.RetentionStore
	admission *artifact.EnvelopeStore
	journal   *artifactAdmissionJournal
	resume    artifact.BudgetedErasureStore
}

// NewIndexedArtifactStore composes physical retention storage with its PostgreSQL index.
func NewIndexedArtifactStore(index *ArtifactIndex, artifacts artifact.RetentionStore) (*IndexedArtifactStore, error) {
	if index == nil || index.store == nil || nilRetentionStore(artifacts) {
		return nil, ErrInvalidDatabase
	}
	return &IndexedArtifactStore{index: index, artifacts: artifacts}, nil
}
func (s *IndexedArtifactStore) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	if s == nil {
		return false, ErrInvalidDatabase
	}
	if s.admission != nil {
		return s.admission.Put(ctx, value, at)
	}
	created, err := s.artifacts.Put(ctx, value, at)
	if err != nil {
		return false, err
	}
	if _, err := s.index.RegisterArtifact(ctx, value); err != nil {
		return false, err
	}
	return created, nil
}
func (s *IndexedArtifactStore) Get(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) (artifact.Artifact, error) {
	if s == nil {
		return artifact.Artifact{}, ErrInvalidDatabase
	}
	if s.admission != nil {
		return s.getIndexedAdmittedArtifact(ctx, scope, identity, at)
	}
	metadata, err := s.index.GetArtifactMetadata(ctx, scope, identity)
	if err != nil {
		return artifact.Artifact{}, err
	}
	value, err := s.artifacts.Get(ctx, scope, identity, at)
	if err != nil {
		return artifact.Artifact{}, err
	}
	if !metadata.matches(value) {
		return artifact.Artifact{}, ErrArtifactIndexConflict
	}
	return value, nil
}
func (s *IndexedArtifactStore) Delete(ctx context.Context, authorization artifact.DeletionAuthorization, at time.Time) (artifact.DeletionReceipt, error) {
	if s == nil {
		return artifact.DeletionReceipt{}, ErrInvalidDatabase
	}
	if s.admission != nil {
		return s.admission.Delete(ctx, authorization, at)
	}
	if _, err := s.index.RecordDeletionAuthorization(ctx, authorization); err != nil {
		return artifact.DeletionReceipt{}, err
	}
	receipt, err := s.artifacts.Delete(ctx, authorization, at)
	if err != nil {
		return artifact.DeletionReceipt{}, err
	}
	if _, err := s.index.RecordDeletionReceipt(ctx, receipt); err != nil {
		return artifact.DeletionReceipt{}, err
	}
	return receipt, nil
}
func nilRetentionStore(store artifact.RetentionStore) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

var _ artifact.RetentionStore = (*IndexedArtifactStore)(nil)

// Forwarders exist only for explicitly composed admission-mode instances.
func (s *IndexedArtifactStore) ReadAdmission(ctx context.Context, scope audit.ReviewScope, namespace, identity string) (artifact.ArtifactAdmission, bool, error) {
	if s == nil || s.admission == nil {
		return artifact.ArtifactAdmission{}, false, artifact.ErrErasureJournalRequired
	}
	return s.admission.ReadAdmission(ctx, scope, namespace, identity)
}
func (s *IndexedArtifactStore) PrepareErasure(ctx context.Context, g artifact.ErasureAuthorizationV2, at time.Time) (artifact.ErasureOperation, error) {
	if s == nil || s.admission == nil {
		return artifact.ErasureOperation{}, artifact.ErrErasureJournalRequired
	}
	return s.admission.PrepareErasure(ctx, g, at)
}
func (s *IndexedArtifactStore) ReadPreparedErasure(ctx context.Context, ref artifact.ErasureOperationRef) (artifact.ErasureOperation, bool, error) {
	if s == nil || s.admission == nil {
		return artifact.ErasureOperation{}, false, artifact.ErrErasureJournalRequired
	}
	return s.admission.ReadPreparedErasure(ctx, ref)
}
func (s *IndexedArtifactStore) FindPreparedErasure(ctx context.Context, scope audit.ReviewScope, namespace, identity string) (artifact.ErasureOperation, bool, error) {
	if s == nil || s.admission == nil {
		return artifact.ErasureOperation{}, false, artifact.ErrErasureJournalRequired
	}
	return s.admission.FindPreparedErasure(ctx, scope, namespace, identity)
}

var _ artifact.AdmissionPreparationStore = (*IndexedArtifactStore)(nil)
