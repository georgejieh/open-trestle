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

// recordRefusalOver decides how a refusal is recorded over the delivery's
// existing record: the same planner's record stands (ErrRefusalConflict for
// another reason), and a superseded planner's record is replaced.
func recordRefusalOver(existing, record RefusalRecord, recorded bool) (RefusalRecord, bool, bool, error) {
	if !recorded || existing.plannerIdentity != record.plannerIdentity {
		return RefusalRecord{}, false, true, nil
	}
	if !existing.SameRefusal(record) {
		return RefusalRecord{}, false, false, ErrRefusalConflict
	}
	return existing, false, false, nil
}

func validateRefusalRead(ctx context.Context, scope RepositoryScope, source Source, key, planner string) error {
	if err := validateRecordedRefusalRead(ctx, scope, source, key); err != nil {
		return err
	}
	if !validWebhookDigest(planner) {
		return ErrInvalidRefusalRecord
	}
	return nil
}

func validateRecordedRefusalRead(ctx context.Context, scope RepositoryScope, source Source, key string) error {
	if err := validateInboxRead(ctx, scope, source, key, 1); err != nil {
		return err
	}
	if !validWebhookDigest(key) {
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
	key := retryKey(record.scope, record.source, record.deduplicationKey)
	existing, recorded := s.refusals[key]
	kept, created, write, err := recordRefusalOver(existing, record, recorded)
	if !write {
		return kept, created, err
	}
	if s.refusals == nil {
		s.refusals = make(map[string]RefusalRecord)
	}
	s.refusals[key] = record
	return record, true, nil
}

// RecordedRefusal returns the refusal recorded for a delivery, whichever
// planner identity recorded it.
func (s *MemoryStore) RecordedRefusal(ctx context.Context, scope RepositoryScope, source Source, key string) (RefusalRecord, bool, error) {
	if err := validateRecordedRefusalRead(ctx, scope, source, key); err != nil {
		return RefusalRecord{}, false, err
	}
	if s == nil {
		return RefusalRecord{}, false, ErrInvalidInbox
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, found := s.refusals[retryKey(scope, source, key)]
	return record, found, nil
}

// Refusal returns the refusal recorded for a delivery by a planner identity.
func (s *MemoryStore) Refusal(ctx context.Context, scope RepositoryScope, source Source, key, planner string) (RefusalRecord, bool, error) {
	if err := validateRefusalRead(ctx, scope, source, key, planner); err != nil {
		return RefusalRecord{}, false, err
	}
	record, found, err := s.RecordedRefusal(ctx, scope, source, key)
	if err != nil || !found || record.plannerIdentity != planner {
		return RefusalRecord{}, false, err
	}
	return record, true, nil
}

// ClearRefusal removes the refusal of a delivery if the planner identity
// recorded it.
func (s *MemoryStore) ClearRefusal(ctx context.Context, scope RepositoryScope, source Source, key, planner string) error {
	if err := validateRefusalRead(ctx, scope, source, key, planner); err != nil {
		return err
	}
	if s == nil {
		return ErrInvalidInbox
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if record, found := s.refusals[retryKey(scope, source, key)]; found && record.plannerIdentity == planner {
		delete(s.refusals, retryKey(scope, source, key))
	}
	return nil
}

func (s *FileStore) refusalPath(scope RepositoryScope, source Source, key string) string {
	return filepath.Join(s.root, scope.Identity()+"-"+source.String()+"-"+key+refusalFileSuffix)
}

// RecordRefusal persists a refusal of a stored delivery beside it, atomically.
// Refusal files never match the delivery suffix, so listing and replay
// indexing ignore them. A delivery has at most one: a refusal replaces the
// record a superseded planner identity left, so refusal files never outnumber
// deliveries.
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
	path := s.refusalPath(record.scope, record.source, record.deduplicationKey)
	existing, recorded, err := s.loadRefusal(path, record.scope, record.source, record.deduplicationKey)
	if err != nil {
		return RefusalRecord{}, false, err
	}
	kept, created, write, err := recordRefusalOver(existing, record, recorded)
	if !write {
		return kept, created, err
	}
	if !recorded {
		if counts, err := s.rootCounts(); err != nil {
			return RefusalRecord{}, false, err
		} else if counts.refusals >= maxInboxStoreFiles {
			return RefusalRecord{}, false, ErrInboxStoreCapacity
		}
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

// RecordedRefusal returns the refusal recorded for a delivery, whichever
// planner identity recorded it.
func (s *FileStore) RecordedRefusal(ctx context.Context, scope RepositoryScope, source Source, key string) (RefusalRecord, bool, error) {
	if err := validateRecordedRefusalRead(ctx, scope, source, key); err != nil {
		return RefusalRecord{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return RefusalRecord{}, false, err
	}
	return s.loadRefusal(s.refusalPath(scope, source, key), scope, source, key)
}

// Refusal returns the refusal recorded for a delivery by a planner identity.
func (s *FileStore) Refusal(ctx context.Context, scope RepositoryScope, source Source, key, planner string) (RefusalRecord, bool, error) {
	if err := validateRefusalRead(ctx, scope, source, key, planner); err != nil {
		return RefusalRecord{}, false, err
	}
	record, found, err := s.RecordedRefusal(ctx, scope, source, key)
	if err != nil || !found || record.plannerIdentity != planner {
		return RefusalRecord{}, false, err
	}
	return record, true, nil
}

// ClearRefusal removes the refusal file of a delivery if the planner identity
// recorded it.
func (s *FileStore) ClearRefusal(ctx context.Context, scope RepositoryScope, source Source, key, planner string) error {
	if err := validateRefusalRead(ctx, scope, source, key, planner); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return err
	}
	path := s.refusalPath(scope, source, key)
	record, found, err := s.loadRefusal(path, scope, source, key)
	if err != nil || !found || record.plannerIdentity != planner {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: remove refusal", ErrInboxStorePersistence)
	}
	return s.syncRoot()
}

// loadRefusal reads a delivery's refusal file and checks it names the delivery.
func (s *FileStore) loadRefusal(path string, scope RepositoryScope, source Source, key string) (RefusalRecord, bool, error) {
	record, found, err := loadRefusalFile(path)
	if err != nil || !found {
		return RefusalRecord{}, false, err
	}
	if record.scope.Identity() != scope.Identity() || record.source != source || record.deduplicationKey != key {
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
