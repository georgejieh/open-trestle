package postgres

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/webhook"
)

const (
	minimumWebhookRetention = time.Minute
	maximumWebhookRetention = 30 * 24 * time.Hour
	maximumWebhookEntries   = 10_000
)

// WebhookClock supplies protected inbox retrieval time.
type WebhookClock interface{ Now() time.Time }

// WebhookStoreOptions defines protection and retention for verified delivery bodies.
type WebhookStoreOptions struct {
	Classification artifact.Classification
	Protection     artifact.Protection
	Retention      time.Duration
	Clock          WebhookClock
}

// WebhookStore keeps canonical delivery bodies in a protected artifact store.
type WebhookStore struct {
	store     *Store
	artifacts artifact.Store
	options   WebhookStoreOptions
}

// NewWebhookStore binds tenant-scoped PostgreSQL metadata to a protected artifact store.
func NewWebhookStore(database *sql.DB, artifacts artifact.Store, options WebhookStoreOptions) (*WebhookStore, error) {
	store, err := New(database)
	validRetention := options.Retention >= minimumWebhookRetention && options.Retention <= maximumWebhookRetention
	if err != nil || nilArtifactStore(artifacts) || options.Classification.String() == "" || options.Protection.String() == "" || !validRetention || nilDynamicValue(options.Clock) {
		return nil, webhook.ErrInvalidInbox
	}
	return &WebhookStore{store: store, artifacts: artifacts, options: options}, nil
}

func (s *WebhookStore) Put(ctx context.Context, delivery webhook.VerifiedDelivery, at time.Time) (webhook.StoredDelivery, bool, error) {
	if err := validateWebhookOperation(ctx, s); err != nil {
		return webhook.StoredDelivery{}, false, err
	}
	if delivery.Validate() != nil {
		return webhook.StoredDelivery{}, false, webhook.ErrInvalidVerifiedDelivery
	}
	if existing, found, err := s.loadWebhookMapping(ctx, delivery.Scope(), delivery.Source(), delivery.DeduplicationKey()); err != nil {
		return webhook.StoredDelivery{}, false, err
	} else if found {
		stored, err := s.loadWebhookArtifact(ctx, delivery.Scope(), delivery.Source(), delivery.DeduplicationKey(), existing, s.options.Clock.Now().UTC())
		if err != nil {
			return webhook.StoredDelivery{}, false, err
		}
		if !stored.Delivery().SameContent(delivery) {
			return webhook.StoredDelivery{}, false, webhook.ErrDeliveryConflict
		}
		return stored, false, nil
	}
	stored, err := webhook.NewStoredDelivery(delivery, at)
	if err != nil {
		return webhook.StoredDelivery{}, false, err
	}
	value, reviewScope, err := s.newWebhookArtifact(stored)
	if err != nil {
		return webhook.StoredDelivery{}, false, err
	}
	if _, err := s.artifacts.Put(ctx, value, at); err != nil {
		return webhook.StoredDelivery{}, false, err
	}
	if ctx.Err() != nil {
		return webhook.StoredDelivery{}, false, ErrInvalidDatabase
	}
	lockIdentity := "webhook:" + delivery.Scope().Identity() + ":" + delivery.Source().String()
	var existing webhookMapping
	created := false
	err = s.store.retrySerializableMutation(ctx, delivery.Scope().TenantID(), ErrDatabaseUnavailable, func(tx *sql.Tx) error {
		existing = webhookMapping{}
		created = false
		if err := lockScopeTransaction(ctx, tx, lockIdentity); err != nil {
			return err
		}
		if err := ensureScopeTransaction(ctx, tx, reviewScope); err != nil {
			return err
		}
		mapping, found, err := queryWebhookMappingTransaction(ctx, tx, delivery.Scope(), delivery.Source(), delivery.DeduplicationKey())
		if err != nil {
			return err
		}
		if found {
			existing = mapping
			return nil
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*)
FROM open_trestle_webhook_deliveries
WHERE tenant_id = $1 AND repository_id = $2 AND source = $3 AND expires_at > $4`, delivery.Scope().TenantID(), delivery.Scope().RepositoryID(), delivery.Source().String(), s.options.Clock.Now().UTC()).Scan(&count); err != nil {
			return classifyTransactionError(err)
		}
		if count >= maximumWebhookEntries {
			return webhook.ErrInboxStoreCapacity
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO open_trestle_webhook_deliveries
(tenant_id, repository_id, review_run_id, review_scope_identity, repository_scope_identity, source, deduplication_key, delivery_identity, artifact_identity, accepted_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			delivery.Scope().TenantID(), delivery.Scope().RepositoryID(), reviewScope.ReviewRunID(),
			reviewScope.Identity(), delivery.Scope().Identity(), delivery.Source().String(),
			delivery.DeduplicationKey(), delivery.Identity(), value.Identity(),
			stored.Receipt().AcceptedAt(), value.ExpiresAt(),
		); err != nil {
			return classifyTransactionError(err)
		}
		created = true
		return nil
	})
	if err != nil {
		return webhook.StoredDelivery{}, false, err
	}
	if !created {
		// The artifact index may need the connection released by the metadata commit.
		persisted, err := s.loadWebhookArtifact(ctx, delivery.Scope(), delivery.Source(), delivery.DeduplicationKey(), existing, s.options.Clock.Now().UTC())
		if err != nil {
			return webhook.StoredDelivery{}, false, err
		}
		if !persisted.Delivery().SameContent(delivery) {
			return webhook.StoredDelivery{}, false, webhook.ErrDeliveryConflict
		}
		return persisted, false, nil
	}
	return stored, true, nil
}

func (s *WebhookStore) Get(ctx context.Context, scope webhook.RepositoryScope, source webhook.Source, key string) (webhook.StoredDelivery, bool, error) {
	if err := validateWebhookRead(ctx, s, scope, source, key, 1); err != nil {
		return webhook.StoredDelivery{}, false, err
	}
	mapping, found, err := s.loadWebhookMapping(ctx, scope, source, key)
	if err != nil || !found {
		return webhook.StoredDelivery{}, found, err
	}
	stored, err := s.loadWebhookArtifact(ctx, scope, source, key, mapping, s.options.Clock.Now().UTC())
	if err != nil {
		return webhook.StoredDelivery{}, false, err
	}
	return stored, true, nil
}

func (s *WebhookStore) List(ctx context.Context, scope webhook.RepositoryScope, source webhook.Source, after string, limit int) ([]webhook.StoredDelivery, error) {
	if err := validateWebhookRead(ctx, s, scope, source, after, limit); err != nil {
		return nil, err
	}
	at := s.options.Clock.Now().UTC()
	tx, err := s.store.beginTenant(ctx, scope.TenantID(), sql.LevelReadCommitted)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT review_run_id, review_scope_identity, repository_scope_identity, deduplication_key, delivery_identity, artifact_identity, accepted_at, expires_at
FROM open_trestle_webhook_deliveries
WHERE tenant_id = $1 AND repository_id = $2 AND source = $3 AND deduplication_key > $4 AND expires_at > $6
ORDER BY deduplication_key ASC LIMIT $5`, scope.TenantID(), scope.RepositoryID(), source.String(), after, limit, at)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer rows.Close()
	mappings := make([]webhookMapping, 0)
	previous := after
	for rows.Next() {
		mapping, err := scanWebhookMapping(rows)
		if err != nil || validateWebhookMapping(mapping, scope, source, mapping.deduplicationKey) != nil || mapping.deduplicationKey <= previous {
			return nil, ErrCorruptRecord
		}
		mappings = append(mappings, mapping)
		previous = mapping.deduplicationKey
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
	stored := make([]webhook.StoredDelivery, len(mappings))
	for index, mapping := range mappings {
		value, err := s.loadWebhookArtifact(ctx, scope, source, mapping.deduplicationKey, mapping, at)
		if err != nil {
			return nil, err
		}
		stored[index] = value
	}
	return stored, nil
}

type webhookMapping struct {
	reviewRunID, reviewScopeIdentity, repositoryScopeIdentity string
	deduplicationKey, deliveryIdentity, artifactIdentity      string
	acceptedAt, expiresAt                                     time.Time
}

type rowScanner interface{ Scan(...any) error }

func scanWebhookMapping(scanner rowScanner) (webhookMapping, error) {
	var mapping webhookMapping
	err := scanner.Scan(
		&mapping.reviewRunID, &mapping.reviewScopeIdentity, &mapping.repositoryScopeIdentity,
		&mapping.deduplicationKey, &mapping.deliveryIdentity, &mapping.artifactIdentity,
		&mapping.acceptedAt, &mapping.expiresAt,
	)
	return mapping, err
}
func queryWebhookMapping(ctx context.Context, tx *sql.Tx, scope webhook.RepositoryScope, source webhook.Source, key string) (webhookMapping, bool, error) {
	mapping, found, err := queryWebhookMappingTransaction(ctx, tx, scope, source, key)
	return mapping, found, redactTransactionError(err)
}
func queryWebhookMappingTransaction(ctx context.Context, tx *sql.Tx, scope webhook.RepositoryScope, source webhook.Source, key string) (webhookMapping, bool, error) {
	row := tx.QueryRowContext(ctx, `SELECT review_run_id, review_scope_identity, repository_scope_identity, deduplication_key, delivery_identity, artifact_identity, accepted_at, expires_at
FROM open_trestle_webhook_deliveries
WHERE tenant_id = $1 AND repository_id = $2 AND source = $3 AND deduplication_key = $4`, scope.TenantID(), scope.RepositoryID(), source.String(), key)
	mapping, err := scanWebhookMapping(row)
	if errors.Is(err, sql.ErrNoRows) {
		return webhookMapping{}, false, nil
	}
	if err != nil {
		return webhookMapping{}, false, classifyTransactionError(err)
	}
	if err := validateWebhookMapping(mapping, scope, source, key); err != nil {
		return webhookMapping{}, false, err
	}
	return mapping, true, nil
}
func validateWebhookMapping(mapping webhookMapping, scope webhook.RepositoryScope, source webhook.Source, key string) error {
	validIdentities := validDigest(mapping.deduplicationKey) && validDigest(mapping.deliveryIdentity) && validDigest(mapping.artifactIdentity)
	validBinding := mapping.deduplicationKey == key && mapping.repositoryScopeIdentity == scope.Identity()
	if !validIdentities || !validBinding || !mapping.expiresAt.After(mapping.acceptedAt) {
		return ErrCorruptRecord
	}
	reviewScope, err := audit.NewReviewScope(scope.TenantID(), scope.RepositoryID(), mapping.reviewRunID)
	if err != nil || mapping.reviewRunID != "webhook-"+key || mapping.reviewScopeIdentity != reviewScope.Identity() || source.Validate() != nil {
		return ErrCorruptRecord
	}
	return nil
}
func (s *WebhookStore) loadWebhookMapping(ctx context.Context, scope webhook.RepositoryScope, source webhook.Source, key string) (webhookMapping, bool, error) {
	tx, err := s.store.beginTenant(ctx, scope.TenantID(), sql.LevelReadCommitted)
	if err != nil {
		return webhookMapping{}, false, err
	}
	defer tx.Rollback()
	mapping, found, err := queryWebhookMapping(ctx, tx, scope, source, key)
	if err != nil {
		return webhookMapping{}, false, err
	}
	if err := commit(tx); err != nil {
		return webhookMapping{}, false, err
	}
	return mapping, found, nil
}
func (s *WebhookStore) newWebhookArtifact(stored webhook.StoredDelivery) (artifact.Artifact, audit.ReviewScope, error) {
	delivery := stored.Delivery()
	reviewScope, err := audit.NewReviewScope(delivery.Scope().TenantID(), delivery.Scope().RepositoryID(), webhook.ReviewRunIDForDelivery(delivery))
	if err != nil {
		return artifact.Artifact{}, audit.ReviewScope{}, err
	}
	encoded, err := webhook.EncodeStoredDelivery(stored)
	if err != nil {
		return artifact.Artifact{}, audit.ReviewScope{}, err
	}
	provenance := []string{delivery.Identity(), delivery.VerifierIdentity(), delivery.BodyDigest(), stored.Receipt().Identity()}
	sort.Strings(provenance)
	canonical := provenance[:0]
	for _, identity := range provenance {
		if len(canonical) == 0 || canonical[len(canonical)-1] != identity {
			canonical = append(canonical, identity)
		}
	}
	value, err := artifact.New(
		reviewScope, artifact.KindWebhookDelivery, "application/json", s.options.Classification,
		artifact.OriginHost, s.options.Protection, canonical, encoded,
		stored.Receipt().AcceptedAt(), stored.Receipt().AcceptedAt().Add(s.options.Retention),
	)
	return value, reviewScope, err
}
func (s *WebhookStore) loadWebhookArtifact(
	ctx context.Context,
	scope webhook.RepositoryScope,
	source webhook.Source,
	key string,
	mapping webhookMapping,
	at time.Time,
) (webhook.StoredDelivery, error) {
	if validateWebhookMapping(mapping, scope, source, key) != nil {
		return webhook.StoredDelivery{}, ErrCorruptRecord
	}
	if !mapping.expiresAt.After(at) {
		return webhook.StoredDelivery{}, webhook.ErrDeliveryExpired
	}
	reviewScope, err := audit.NewReviewScope(scope.TenantID(), scope.RepositoryID(), mapping.reviewRunID)
	if err != nil {
		return webhook.StoredDelivery{}, ErrCorruptRecord
	}
	value, err := s.artifacts.Get(ctx, reviewScope, mapping.artifactIdentity, at)
	if err != nil {
		return webhook.StoredDelivery{}, err
	}
	validType := value.Kind() == artifact.KindWebhookDelivery && value.MediaType() == "application/json"
	validPolicy := value.Classification() == s.options.Classification && value.Protection() == s.options.Protection
	validArtifact := validType && validPolicy && value.Origin() == artifact.OriginHost && value.ExpiresAt().Equal(mapping.expiresAt) && slices.Contains(value.Provenance(), mapping.deliveryIdentity)
	if !validArtifact {
		return webhook.StoredDelivery{}, ErrCorruptRecord
	}
	stored, err := webhook.ParseStoredDelivery(value.Payload())
	if err != nil {
		return webhook.StoredDelivery{}, ErrCorruptRecord
	}
	delivery := stored.Delivery()
	validDelivery := delivery.Identity() == mapping.deliveryIdentity && delivery.DeduplicationKey() == key
	validScope := delivery.Scope().Identity() == scope.Identity() && delivery.Source() == source
	validStored := validDelivery && validScope && stored.Receipt().AcceptedAt().Equal(mapping.acceptedAt)
	if !validStored {
		return webhook.StoredDelivery{}, ErrCorruptRecord
	}
	return stored, nil
}
func validateWebhookOperation(ctx context.Context, store *WebhookStore) error {
	if nilContext(ctx) {
		return webhook.ErrInvalidInboxContext
	}
	if store == nil || store.store == nil || store.store.database == nil || nilArtifactStore(store.artifacts) {
		return webhook.ErrInvalidInbox
	}
	if ctx.Err() != nil {
		return webhook.ErrInboxContextDone
	}
	return nil
}
func validateWebhookRead(ctx context.Context, store *WebhookStore, scope webhook.RepositoryScope, source webhook.Source, cursor string, limit int) error {
	if err := validateWebhookOperation(ctx, store); err != nil {
		return err
	}
	if scope.Validate() != nil || source.Validate() != nil || cursor != "" && !validDigest(cursor) || limit <= 0 || limit > 100 {
		return webhook.ErrInvalidInboxList
	}
	return nil
}

var _ webhook.Store = (*WebhookStore)(nil)
