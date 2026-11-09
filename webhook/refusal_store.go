package webhook

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const refusalFileSuffix = ".refusal.json"

func refusalKey(scope RepositoryScope, source Source, key, planner string) string {
	return scope.Identity() + "|" + source.String() + "|" + key + "|" + planner
}

// matchRecordedRefusal returns the existing record for the same refusal, or
// ErrRefusalConflict for a different one.
func matchRecordedRefusal(existing, record RefusalRecord) (RefusalRecord, bool, error) {
	if !existing.SameRefusal(record) {
		return RefusalRecord{}, false, ErrRefusalConflict
	}
	return existing, false, nil
}

func validateRefusalRead(ctx context.Context, scope RepositoryScope, source Source, key, planner string) error {
	if err := validateInboxRead(ctx, scope, source, key, 1); err != nil {
		return err
	}
	if !validWebhookDigest(key) || !validWebhookDigest(planner) {
		return ErrInvalidRefusalRecord
	}
	return nil
}

// RecordRefusal records a refusal of a delivery this store holds.
func (s *MemoryStore) RecordRefusal(ctx context.Context, record RefusalRecord) (RefusalRecord, bool, error) {
	if err := validateInboxOperation(ctx); err != nil {
		return RefusalRecord{}, false, err
	}
	if s == nil {
		return RefusalRecord{}, false, ErrInvalidInbox
	}
	if record.Validate() != nil {
		return RefusalRecord{}, false, ErrInvalidRefusalRecord
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, found := s.entries[record.deduplicationKey]
	if !found || stored.delivery.Identity() != record.deliveryIdentity || stored.delivery.Scope().Identity() != record.scope.Identity() || stored.delivery.Source() != record.source {
		return RefusalRecord{}, false, ErrInvalidRefusalRecord
	}
	key := refusalKey(record.scope, record.source, record.deduplicationKey, record.plannerIdentity)
	if existing, recorded := s.refusals[key]; recorded {
		return matchRecordedRefusal(existing, record)
	}
	if s.refusals == nil {
		s.refusals = make(map[string]RefusalRecord)
	}
	s.refusals[key] = record
	return record, true, nil
}

// Refusal returns the refusal recorded for a delivery and planner identity.
func (s *MemoryStore) Refusal(ctx context.Context, scope RepositoryScope, source Source, key, planner string) (RefusalRecord, bool, error) {
	if err := validateRefusalRead(ctx, scope, source, key, planner); err != nil {
		return RefusalRecord{}, false, err
	}
	if s == nil {
		return RefusalRecord{}, false, ErrInvalidInbox
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, found := s.refusals[refusalKey(scope, source, key, planner)]
	return record, found, nil
}

func (s *FileStore) refusalPath(scope RepositoryScope, source Source, key, planner string) string {
	return filepath.Join(s.root, scope.Identity()+"-"+source.String()+"-"+key+"-"+planner+refusalFileSuffix)
}

// RecordRefusal persists a refusal of a stored delivery beside it, atomically.
// Refusal files never match the delivery suffix, so listing and replay
// indexing ignore them; they count toward the sidecar bound, never the
// delivery bound.
func (s *FileStore) RecordRefusal(ctx context.Context, record RefusalRecord) (RefusalRecord, bool, error) {
	if err := validateInboxOperation(ctx); err != nil {
		return RefusalRecord{}, false, err
	}
	if record.Validate() != nil {
		return RefusalRecord{}, false, ErrInvalidRefusalRecord
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return RefusalRecord{}, false, err
	}
	stored, found, err := s.loadExpected(s.deliveryPath(record.scope, record.source, record.deduplicationKey), record.scope, record.source, record.deduplicationKey)
	if err != nil {
		return RefusalRecord{}, false, err
	}
	if !found || stored.Delivery().Identity() != record.deliveryIdentity {
		return RefusalRecord{}, false, ErrInvalidRefusalRecord
	}
	path := s.refusalPath(record.scope, record.source, record.deduplicationKey, record.plannerIdentity)
	if existing, recorded, err := loadRefusalFile(path); err != nil {
		return RefusalRecord{}, false, err
	} else if recorded {
		return matchRecordedRefusal(existing, record)
	}
	if _, sidecars, err := s.rootFiles(); err != nil {
		return RefusalRecord{}, false, err
	} else if sidecars >= maxInboxStoreSidecars {
		return RefusalRecord{}, false, ErrInboxStoreCapacity
	}
	encoded, err := EncodeRefusalRecord(record)
	if err != nil {
		return RefusalRecord{}, false, err
	}
	if err := s.persist(path, encoded); err != nil {
		return RefusalRecord{}, false, err
	}
	return record, true, nil
}

// Refusal returns the refusal recorded for a delivery and planner identity.
func (s *FileStore) Refusal(ctx context.Context, scope RepositoryScope, source Source, key, planner string) (RefusalRecord, bool, error) {
	if err := validateRefusalRead(ctx, scope, source, key, planner); err != nil {
		return RefusalRecord{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return RefusalRecord{}, false, err
	}
	record, found, err := loadRefusalFile(s.refusalPath(scope, source, key, planner))
	if err != nil || !found {
		return RefusalRecord{}, false, err
	}
	if record.scope.Identity() != scope.Identity() || record.source != source || record.deduplicationKey != key || record.plannerIdentity != planner {
		return RefusalRecord{}, false, ErrInvalidRefusalRecord
	}
	return record, true, nil
}

func loadRefusalFile(path string) (RefusalRecord, bool, error) {
	information, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return RefusalRecord{}, false, nil
	}
	if err != nil {
		return RefusalRecord{}, false, fmt.Errorf("%w: inspect refusal", ErrInboxStorePersistence)
	}
	if !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 || information.Size() <= 0 || information.Size() > 4096 {
		return RefusalRecord{}, false, ErrInvalidRefusalRecord
	}
	file, err := os.Open(path)
	if err != nil {
		return RefusalRecord{}, false, fmt.Errorf("%w: open refusal", ErrInboxStorePersistence)
	}
	opened, statErr := file.Stat()
	encoded, readErr := io.ReadAll(io.LimitReader(file, 4097))
	closeErr := file.Close()
	if statErr != nil || !os.SameFile(information, opened) {
		return RefusalRecord{}, false, ErrInvalidRefusalRecord
	}
	if readErr != nil || closeErr != nil {
		return RefusalRecord{}, false, fmt.Errorf("%w: read refusal", ErrInboxStorePersistence)
	}
	record, err := ParseRefusalRecord(encoded)
	if err != nil {
		return RefusalRecord{}, false, err
	}
	return record, true, nil
}

var (
	_ RefusalStore = (*MemoryStore)(nil)
	_ RefusalStore = (*FileStore)(nil)
)
