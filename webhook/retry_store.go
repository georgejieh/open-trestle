package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// ErrInvalidRetryRecord identifies a malformed or cross-wired retry record.
var ErrInvalidRetryRecord = errors.New("invalid webhook delivery retry record")

const retryFileSuffix = ".retry.json"

// RetryRecord is one delivery's durable retry state for one planner identity:
// how many of its own failures it has had and when it may next be attempted.
// It carries identities and counts only.
type RetryRecord struct {
	deliveryIdentity, deduplicationKey, plannerIdentity string
	scope                                               RepositoryScope
	source                                              Source
	failures                                            uint8
	notBeforeMillis                                     int64
}

// NewRetryRecord records the retry state of a stored delivery.
func NewRetryRecord(stored StoredDelivery, plannerIdentity string, failures uint8, notBefore time.Time) (RetryRecord, error) {
	if stored.Validate() != nil {
		return RetryRecord{}, ErrInvalidRetryRecord
	}
	delivery := stored.Delivery()
	record := RetryRecord{deliveryIdentity: delivery.Identity(), deduplicationKey: delivery.DeduplicationKey(), plannerIdentity: plannerIdentity, scope: delivery.Scope(), source: delivery.Source(), failures: failures, notBeforeMillis: notBefore.UnixMilli()}
	if record.Validate() != nil {
		return RetryRecord{}, ErrInvalidRetryRecord
	}
	return record, nil
}

// RestoreRetryRecord rebuilds a stored retry record from its fields.
func RestoreRetryRecord(scope RepositoryScope, source Source, deduplicationKey, deliveryIdentity, plannerIdentity string, failures uint8, notBeforeMillis int64) (RetryRecord, error) {
	record := RetryRecord{deliveryIdentity: deliveryIdentity, deduplicationKey: deduplicationKey, plannerIdentity: plannerIdentity, scope: scope, source: source, failures: failures, notBeforeMillis: notBeforeMillis}
	if record.Validate() != nil {
		return RetryRecord{}, ErrInvalidRetryRecord
	}
	return record, nil
}

func (r RetryRecord) DeliveryIdentity() string { return r.deliveryIdentity }
func (r RetryRecord) DeduplicationKey() string { return r.deduplicationKey }
func (r RetryRecord) PlannerIdentity() string  { return r.plannerIdentity }
func (r RetryRecord) Scope() RepositoryScope   { return r.scope }
func (r RetryRecord) Source() Source           { return r.source }
func (r RetryRecord) Failures() uint8          { return r.failures }
func (r RetryRecord) NotBefore() time.Time     { return time.UnixMilli(r.notBeforeMillis).UTC() }
func (r RetryRecord) NotBeforeMillis() int64   { return r.notBeforeMillis }
func (r RetryRecord) String() string           { return "webhook delivery retry record" }
func (r RetryRecord) GoString() string         { return "webhook.RetryRecord{<redacted>}" }

func (r RetryRecord) Validate() error {
	if !validWebhookDigest(r.deliveryIdentity) || !validWebhookDigest(r.deduplicationKey) || !validWebhookDigest(r.plannerIdentity) || r.scope.Validate() != nil || r.source.Validate() != nil ||
		r.failures == 0 || r.failures > maxSupervisorRetries || r.notBeforeMillis <= 0 {
		return ErrInvalidRetryRecord
	}
	return nil
}

type retryRecordWire struct {
	Contract         string `json:"contract"`
	SchemaVersion    int    `json:"schema_version"`
	TenantID         string `json:"tenant_id"`
	RepositoryID     string `json:"repository_id"`
	Source           string `json:"source"`
	DeduplicationKey string `json:"deduplication_key"`
	DeliveryIdentity string `json:"delivery_identity"`
	PlannerIdentity  string `json:"planner_identity"`
	Failures         uint8  `json:"failures"`
	NotBeforeMillis  int64  `json:"not_before_milliseconds"`
}

// EncodeRetryRecord returns the one canonical JSON representation.
func EncodeRetryRecord(r RetryRecord) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(retryRecordWire{"open-trestle/webhook-delivery-retry", 1, r.scope.TenantID(), r.scope.RepositoryID(), r.source.String(), r.deduplicationKey, r.deliveryIdentity, r.plannerIdentity, r.failures, r.notBeforeMillis})
}

// ParseRetryRecord accepts only the canonical representation.
func ParseRetryRecord(encoded []byte) (RetryRecord, error) {
	if len(encoded) == 0 || len(encoded) > 4096 {
		return RetryRecord{}, ErrInvalidRetryRecord
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire retryRecordWire
	if decoder.Decode(&wire) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || wire.Contract != "open-trestle/webhook-delivery-retry" || wire.SchemaVersion != 1 {
		return RetryRecord{}, ErrInvalidRetryRecord
	}
	scope, err := NewRepositoryScope(wire.TenantID, wire.RepositoryID)
	if err != nil {
		return RetryRecord{}, ErrInvalidRetryRecord
	}
	source, err := parseSource(wire.Source)
	if err != nil {
		return RetryRecord{}, ErrInvalidRetryRecord
	}
	record, err := RestoreRetryRecord(scope, source, wire.DeduplicationKey, wire.DeliveryIdentity, wire.PlannerIdentity, wire.Failures, wire.NotBeforeMillis)
	if err != nil {
		return RetryRecord{}, err
	}
	canonical, err := EncodeRetryRecord(record)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return RetryRecord{}, ErrInvalidRetryRecord
	}
	return record, nil
}

// RetryStore durably keeps each delivery's own retry state beside the
// delivery, so a restart neither resets the bound nor retries forever.
// RecordRetry replaces the state of a stored delivery; ClearRetry removes it.
type RetryStore interface {
	RecordRetry(context.Context, RetryRecord) error
	Retry(ctx context.Context, scope RepositoryScope, source Source, deduplicationKey, plannerIdentity string) (RetryRecord, bool, error)
	ClearRetry(ctx context.Context, scope RepositoryScope, source Source, deduplicationKey, plannerIdentity string) error
}

// RecordRetry keeps the retry state of a delivery this store holds.
func (s *MemoryStore) RecordRetry(ctx context.Context, record RetryRecord) error {
	if err := validateInboxOperation(ctx); err != nil {
		return err
	}
	if s == nil {
		return ErrInvalidInbox
	}
	if record.Validate() != nil {
		return ErrInvalidRetryRecord
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, found := s.entries[record.deduplicationKey]
	if !found || stored.delivery.Identity() != record.deliveryIdentity || stored.delivery.Scope().Identity() != record.scope.Identity() || stored.delivery.Source() != record.source {
		return ErrInvalidRetryRecord
	}
	if s.retries == nil {
		s.retries = make(map[string]RetryRecord)
	}
	s.retries[refusalKey(record.scope, record.source, record.deduplicationKey, record.plannerIdentity)] = record
	return nil
}

// Retry returns the retry state of a delivery for a planner identity.
func (s *MemoryStore) Retry(ctx context.Context, scope RepositoryScope, source Source, key, planner string) (RetryRecord, bool, error) {
	if err := validateRefusalRead(ctx, scope, source, key, planner); err != nil {
		return RetryRecord{}, false, err
	}
	if s == nil {
		return RetryRecord{}, false, ErrInvalidInbox
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, found := s.retries[refusalKey(scope, source, key, planner)]
	return record, found, nil
}

// ClearRetry removes the retry state of a delivery for a planner identity.
func (s *MemoryStore) ClearRetry(ctx context.Context, scope RepositoryScope, source Source, key, planner string) error {
	if err := validateRefusalRead(ctx, scope, source, key, planner); err != nil {
		return err
	}
	if s == nil {
		return ErrInvalidInbox
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.retries, refusalKey(scope, source, key, planner))
	return nil
}

func (s *FileStore) retryPath(scope RepositoryScope, source Source, key, planner string) string {
	return filepath.Join(s.root, scope.Identity()+"-"+source.String()+"-"+key+"-"+planner+retryFileSuffix)
}

// RecordRetry atomically replaces the retry file beside a stored delivery.
func (s *FileStore) RecordRetry(ctx context.Context, record RetryRecord) error {
	if err := validateInboxOperation(ctx); err != nil {
		return err
	}
	if record.Validate() != nil {
		return ErrInvalidRetryRecord
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return err
	}
	stored, found, err := s.loadExpected(s.deliveryPath(record.scope, record.source, record.deduplicationKey), record.scope, record.source, record.deduplicationKey)
	if err != nil {
		return err
	}
	if !found || stored.Delivery().Identity() != record.deliveryIdentity {
		return ErrInvalidRetryRecord
	}
	path := s.retryPath(record.scope, record.source, record.deduplicationKey, record.plannerIdentity)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		entries, readErr := os.ReadDir(s.root)
		if readErr != nil {
			return fmt.Errorf("%w: read root", ErrInboxStorePersistence)
		}
		if len(entries) >= maxInboxStoreFiles {
			return ErrInboxStoreCapacity
		}
	}
	encoded, err := EncodeRetryRecord(record)
	if err != nil {
		return err
	}
	return s.persist(path, encoded)
}

// Retry reads the retry file of a delivery for a planner identity.
func (s *FileStore) Retry(ctx context.Context, scope RepositoryScope, source Source, key, planner string) (RetryRecord, bool, error) {
	if err := validateRefusalRead(ctx, scope, source, key, planner); err != nil {
		return RetryRecord{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return RetryRecord{}, false, err
	}
	path := s.retryPath(scope, source, key, planner)
	information, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return RetryRecord{}, false, nil
	}
	if err != nil {
		return RetryRecord{}, false, fmt.Errorf("%w: inspect retry", ErrInboxStorePersistence)
	}
	if !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 || information.Size() <= 0 || information.Size() > 4096 {
		return RetryRecord{}, false, ErrInvalidRetryRecord
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return RetryRecord{}, false, fmt.Errorf("%w: read retry", ErrInboxStorePersistence)
	}
	record, err := ParseRetryRecord(encoded)
	if err != nil {
		return RetryRecord{}, false, err
	}
	if record.scope.Identity() != scope.Identity() || record.source != source || record.deduplicationKey != key || record.plannerIdentity != planner {
		return RetryRecord{}, false, ErrInvalidRetryRecord
	}
	return record, true, nil
}

// ClearRetry removes the retry file of a delivery for a planner identity.
func (s *FileStore) ClearRetry(ctx context.Context, scope RepositoryScope, source Source, key, planner string) error {
	if err := validateRefusalRead(ctx, scope, source, key, planner); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return err
	}
	if err := os.Remove(s.retryPath(scope, source, key, planner)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: remove retry", ErrInboxStorePersistence)
	}
	return s.syncRoot()
}

var (
	_ RetryStore = (*MemoryStore)(nil)
	_ RetryStore = (*FileStore)(nil)
)
