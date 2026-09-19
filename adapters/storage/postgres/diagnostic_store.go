package postgres

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
)

const (
	minimumDiagnosticRetention = time.Minute
	maximumDiagnosticRetention = 365 * 24 * time.Hour
)

// DiagnosticClock supplies artifact creation and expiry time.
type DiagnosticClock interface{ Now() time.Time }

// DiagnosticStoreOptions defines protection and retention for verified diagnostic content.
type DiagnosticStoreOptions struct {
	Classification artifact.Classification
	Protection     artifact.Protection
	Retention      time.Duration
	Clock          DiagnosticClock
}

// DiagnosticStore keeps only diagnostic-to-artifact identities in PostgreSQL.
type DiagnosticStore struct {
	store     *Store
	artifacts artifact.Store
	options   DiagnosticStoreOptions
}

// NewDiagnosticStore binds PostgreSQL metadata to a protected artifact store.
func NewDiagnosticStore(database *sql.DB, artifacts artifact.Store, options DiagnosticStoreOptions) (*DiagnosticStore, error) {
	store, err := New(database)
	validRetention := options.Retention >= minimumDiagnosticRetention && options.Retention <= maximumDiagnosticRetention
	if err != nil || nilArtifactStore(artifacts) || options.Classification.String() == "" || options.Protection.String() == "" || !validRetention || nilDynamicValue(options.Clock) {
		return nil, diagnostics.ErrInvalidStore
	}
	return &DiagnosticStore{store: store, artifacts: artifacts, options: options}, nil
}

func (s *DiagnosticStore) PutDiagnosticSet(ctx context.Context, set diagnostics.Set) (bool, error) {
	if err := validateDiagnosticOperation(ctx, s); err != nil {
		return false, err
	}
	if set.Validate() != nil {
		return false, diagnostics.ErrInvalidSet
	}
	if existing, found, err := s.loadDiagnosticMapping(ctx, set.Scope()); err != nil {
		return false, err
	} else if found {
		if existing.setIdentity != set.Identity() {
			return false, diagnostics.ErrSetConflict
		}
		if _, err := s.loadDiagnosticArtifact(ctx, set.Scope(), existing, s.options.Clock.Now().UTC()); err != nil {
			return false, err
		}
		return false, nil
	}
	at := s.options.Clock.Now().UTC()
	value, err := s.newDiagnosticArtifact(set, at)
	if err != nil {
		return false, err
	}
	if _, err := s.artifacts.Put(ctx, value, at); err != nil {
		return false, err
	}
	if ctx.Err() != nil {
		return false, ErrInvalidDatabase
	}
	var existing diagnosticMapping
	created := false
	err = s.store.retrySerializableMutation(ctx, set.Scope().TenantID(), ErrDatabaseUnavailable, func(tx *sql.Tx) error {
		existing = diagnosticMapping{}
		created = false
		if err := lockScopeTransaction(ctx, tx, "diagnostics:"+set.Scope().Identity()); err != nil {
			return err
		}
		if err := ensureScopeTransaction(ctx, tx, set.Scope()); err != nil {
			return err
		}
		mapping, found, err := queryDiagnosticMappingTransaction(ctx, tx, set.Scope())
		if err != nil {
			return err
		}
		if found {
			if mapping.setIdentity != set.Identity() {
				return diagnostics.ErrSetConflict
			}
			existing = mapping
			return nil
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO open_trestle_diagnostic_sets
(tenant_id, repository_id, review_run_id, scope_identity, set_identity, artifact_identity, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			set.Scope().TenantID(), set.Scope().RepositoryID(), set.Scope().ReviewRunID(),
			set.Scope().Identity(), set.Identity(), value.Identity(), value.ExpiresAt(),
		); err != nil {
			return classifyTransactionError(err)
		}
		created = true
		return nil
	})
	if err != nil {
		return false, err
	}
	if !created {
		// The artifact index may need the connection released by the metadata commit.
		_, err := s.loadDiagnosticArtifact(ctx, set.Scope(), existing, s.options.Clock.Now().UTC())
		return false, err
	}
	return true, nil
}

func (s *DiagnosticStore) GetDiagnosticSet(ctx context.Context, scope audit.ReviewScope) (diagnostics.Set, error) {
	if err := validateDiagnosticScope(ctx, s, scope); err != nil {
		return diagnostics.Set{}, err
	}
	mapping, found, err := s.loadDiagnosticMapping(ctx, scope)
	if err != nil {
		return diagnostics.Set{}, err
	}
	if !found {
		return diagnostics.Set{}, diagnostics.ErrSetNotFound
	}
	return s.loadDiagnosticArtifact(ctx, scope, mapping, s.options.Clock.Now().UTC())
}

type diagnosticMapping struct {
	setIdentity, artifactIdentity string
	expiresAt                     time.Time
}

func (s *DiagnosticStore) loadDiagnosticMapping(ctx context.Context, scope audit.ReviewScope) (diagnosticMapping, bool, error) {
	tx, err := s.store.beginTenant(ctx, scope.TenantID(), sql.LevelReadCommitted)
	if err != nil {
		return diagnosticMapping{}, false, err
	}
	defer tx.Rollback()
	mapping, found, err := queryDiagnosticMapping(ctx, tx, scope)
	if err != nil {
		return diagnosticMapping{}, false, err
	}
	if err := commit(tx); err != nil {
		return diagnosticMapping{}, false, err
	}
	return mapping, found, nil
}
func queryDiagnosticMapping(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope) (diagnosticMapping, bool, error) {
	mapping, found, err := queryDiagnosticMappingTransaction(ctx, tx, scope)
	return mapping, found, redactTransactionError(err)
}
func queryDiagnosticMappingTransaction(ctx context.Context, tx *sql.Tx, scope audit.ReviewScope) (diagnosticMapping, bool, error) {
	var mapping diagnosticMapping
	err := tx.QueryRowContext(
		ctx,
		`SELECT set_identity, artifact_identity, expires_at
FROM open_trestle_diagnostic_sets
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`,
		scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(),
	).Scan(&mapping.setIdentity, &mapping.artifactIdentity, &mapping.expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return diagnosticMapping{}, false, nil
	}
	if err != nil {
		return diagnosticMapping{}, false, classifyTransactionError(err)
	}
	if !validDigest(mapping.setIdentity) || !validDigest(mapping.artifactIdentity) || mapping.expiresAt.IsZero() {
		return diagnosticMapping{}, false, ErrCorruptRecord
	}
	return mapping, true, nil
}
func (s *DiagnosticStore) newDiagnosticArtifact(set diagnostics.Set, at time.Time) (artifact.Artifact, error) {
	encoded, err := diagnostics.EncodeSet(set)
	if err != nil {
		return artifact.Artifact{}, err
	}
	provenance := []string{set.Identity(), set.SnapshotIdentity(), set.VerifiedSetIdentity()}
	sort.Strings(provenance)
	canonical := provenance[:0]
	for _, identity := range provenance {
		if len(canonical) == 0 || canonical[len(canonical)-1] != identity {
			canonical = append(canonical, identity)
		}
	}
	return artifact.New(
		set.Scope(), artifact.KindVerifiedFindingSet, "application/json", s.options.Classification,
		artifact.OriginIndependentVerifier, s.options.Protection, canonical, encoded, at, at.Add(s.options.Retention),
	)
}
func (s *DiagnosticStore) loadDiagnosticArtifact(ctx context.Context, scope audit.ReviewScope, mapping diagnosticMapping, at time.Time) (diagnostics.Set, error) {
	value, err := s.artifacts.Get(ctx, scope, mapping.artifactIdentity, at)
	if err != nil {
		return diagnostics.Set{}, err
	}
	provenance := value.Provenance()
	validLineage := slices.Contains(provenance, mapping.setIdentity)
	validType := value.Kind() == artifact.KindVerifiedFindingSet && value.MediaType() == "application/json"
	validPolicy := value.Classification() == s.options.Classification && value.Protection() == s.options.Protection
	validArtifact := validType && validPolicy && value.Origin() == artifact.OriginIndependentVerifier && value.ExpiresAt().Equal(mapping.expiresAt) && validLineage
	if !validArtifact {
		return diagnostics.Set{}, ErrCorruptRecord
	}
	set, err := diagnostics.ParseSet(value.Payload())
	if err != nil || set.Identity() != mapping.setIdentity || set.Scope().Identity() != scope.Identity() {
		return diagnostics.Set{}, ErrCorruptRecord
	}
	return set, nil
}
func validateDiagnosticOperation(ctx context.Context, store *DiagnosticStore) error {
	if nilContext(ctx) {
		return diagnostics.ErrInvalidStoreContext
	}
	if store == nil || store.store == nil || store.store.database == nil || nilArtifactStore(store.artifacts) {
		return diagnostics.ErrInvalidStore
	}
	if ctx.Err() != nil {
		return diagnostics.ErrStoreContextDone
	}
	return nil
}
func validateDiagnosticScope(ctx context.Context, store *DiagnosticStore, scope audit.ReviewScope) error {
	if err := validateDiagnosticOperation(ctx, store); err != nil {
		return err
	}
	if scope.Validate() != nil {
		return diagnostics.ErrInvalidStore
	}
	return nil
}
func nilDynamicValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Ptr && reflected.IsNil()
}

func nilArtifactStore(store artifact.Store) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

var _ diagnostics.Store = (*DiagnosticStore)(nil)
