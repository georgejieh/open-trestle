package webhook

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/internal/filelock"
)

const (
	maxInboxStoreFiles = 10000
	inboxLockFileName  = ".inbox-writer.lock"
	deliveryFileSuffix = ".delivery.json"
)

var (
	// ErrInvalidInboxStoreRoot identifies an empty, symlinked, replaced, or unsafe root.
	ErrInvalidInboxStoreRoot = errors.New("invalid webhook inbox store root")
	// ErrInboxStoreLocked identifies a root already owned by a writer process.
	ErrInboxStoreLocked = errors.New("webhook inbox store locked")
	// ErrInboxStoreClosed identifies use after releasing the writer lock.
	ErrInboxStoreClosed = errors.New("webhook inbox store closed")
	// ErrInboxStorePersistence identifies a failed durable filesystem operation.
	ErrInboxStorePersistence = errors.New("webhook inbox store persistence failure")
)

// FileStore is an exclusive-writer, crash-safe local delivery store.
type FileStore struct {
	mu             sync.Mutex
	root, lockPath string
	rootInfo       os.FileInfo
	lockFile       *filelock.Lock
	closed         bool
}

func NewFileStore(root string) (*FileStore, error) {
	if root == "" {
		return nil, ErrInvalidInboxStoreRoot
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, ErrInvalidInboxStoreRoot
	}
	if information, statErr := os.Lstat(absolute); statErr == nil && information.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidInboxStoreRoot
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, ErrInvalidInboxStoreRoot
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create root", ErrInboxStorePersistence)
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("%w: protect root", ErrInboxStorePersistence)
	}
	information, err := os.Lstat(absolute)
	if err != nil || !information.IsDir() || information.Mode()&os.ModeSymlink != 0 || information.Mode().Perm() != 0o700 {
		return nil, ErrInvalidInboxStoreRoot
	}
	lockPath := filepath.Join(absolute, inboxLockFileName)
	lockFile, err := filelock.Acquire(lockPath)
	if errors.Is(err, filelock.ErrLocked) {
		return nil, ErrInboxStoreLocked
	}
	if err != nil {
		return nil, fmt.Errorf("%w: acquire writer lock", ErrInboxStorePersistence)
	}
	store := &FileStore{root: absolute, lockPath: lockPath, rootInfo: information, lockFile: lockFile}
	if err := store.syncRoot(); err != nil {
		_ = store.cleanupLock()
		return nil, err
	}
	return store, nil
}
func (s *FileStore) Close() error {
	if s == nil {
		return ErrInvalidInbox
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrInboxStoreClosed
	}
	s.closed = true
	return s.cleanupLock()
}
func (s *FileStore) Put(ctx context.Context, delivery VerifiedDelivery, at time.Time) (StoredDelivery, bool, error) {
	if err := validateInboxOperation(ctx); err != nil {
		return StoredDelivery{}, false, err
	}
	if delivery.Validate() != nil {
		return StoredDelivery{}, false, ErrInvalidVerifiedDelivery
	}
	receipt, err := newAcceptanceReceipt(delivery, at)
	if err != nil {
		return StoredDelivery{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return StoredDelivery{}, false, err
	}
	path := s.deliveryPath(delivery.Scope(), delivery.Source(), delivery.DeduplicationKey())
	existing, found, err := s.loadExpected(path, delivery.Scope(), delivery.Source(), delivery.DeduplicationKey())
	if err != nil {
		return StoredDelivery{}, false, err
	}
	if found {
		if !existing.Delivery().SameContent(delivery) {
			return StoredDelivery{}, false, ErrDeliveryConflict
		}
		return existing, false, nil
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return StoredDelivery{}, false, fmt.Errorf("%w: read root", ErrInboxStorePersistence)
	}
	if len(entries) >= maxInboxStoreFiles {
		return StoredDelivery{}, false, ErrInboxStoreCapacity
	}
	stored := StoredDelivery{delivery: delivery, receipt: receipt}
	encoded, err := EncodeStoredDelivery(stored)
	if err != nil {
		return StoredDelivery{}, false, err
	}
	if err := s.persist(path, encoded); err != nil {
		return StoredDelivery{}, false, err
	}
	return stored, true, nil
}
func (s *FileStore) Get(ctx context.Context, scope RepositoryScope, source Source, key string) (StoredDelivery, bool, error) {
	if err := validateInboxRead(ctx, scope, source, key, 1); err != nil {
		return StoredDelivery{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return StoredDelivery{}, false, err
	}
	return s.loadExpected(s.deliveryPath(scope, source, key), scope, source, key)
}
func (s *FileStore) List(ctx context.Context, scope RepositoryScope, source Source, after string, limit int) ([]StoredDelivery, error) {
	if err := validateInboxRead(ctx, scope, source, after, limit); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return nil, err
	}
	directoryEntries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("%w: read root", ErrInboxStorePersistence)
	}
	if len(directoryEntries) > maxInboxStoreFiles+1 {
		return nil, ErrInboxStoreCapacity
	}
	prefix := scope.Identity() + "-" + source.String() + "-"
	paths := make([]string, 0)
	for _, entry := range directoryEntries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, deliveryFileSuffix) {
			continue
		}
		key := strings.TrimSuffix(strings.TrimPrefix(name, prefix), deliveryFileSuffix)
		if !validWebhookDigest(key) {
			return nil, ErrInvalidStoredDeliveryEncoding
		}
		if key > after {
			paths = append(paths, filepath.Join(s.root, name))
		}
	}
	sort.Strings(paths)
	if len(paths) > limit {
		paths = paths[:limit]
	}
	stored := make([]StoredDelivery, 0, len(paths))
	for _, path := range paths {
		key := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), prefix), deliveryFileSuffix)
		entry, found, loadErr := s.loadExpected(path, scope, source, key)
		if loadErr != nil {
			return nil, loadErr
		}
		if !found {
			return nil, ErrInboxStorePersistence
		}
		if entry.Delivery().Scope().Identity() != scope.Identity() || entry.Delivery().Source() != source {
			return nil, ErrInvalidStoredDeliveryEncoding
		}
		stored = append(stored, entry)
	}
	return stored, nil
}
func (s *FileStore) deliveryPath(scope RepositoryScope, source Source, key string) string {
	return filepath.Join(s.root, scope.Identity()+"-"+source.String()+"-"+key+deliveryFileSuffix)
}
func (s *FileStore) ensureOpen() error {
	if s == nil {
		return ErrInvalidInbox
	}
	if s.closed || s.lockFile == nil {
		return ErrInboxStoreClosed
	}
	information, err := os.Lstat(s.root)
	if err != nil || !information.IsDir() || information.Mode()&os.ModeSymlink != 0 || information.Mode().Perm() != 0o700 || !os.SameFile(information, s.rootInfo) {
		return ErrInvalidInboxStoreRoot
	}
	lockInformation, err := os.Lstat(s.lockPath)
	if err != nil || !lockInformation.Mode().IsRegular() || lockInformation.Mode().Perm()&0o077 != 0 {
		return ErrInboxStoreLocked
	}
	return nil
}
func (s *FileStore) loadExpected(path string, scope RepositoryScope, source Source, key string) (StoredDelivery, bool, error) {
	stored, found, err := s.loadPath(path)
	if err != nil || !found {
		return stored, found, err
	}
	delivery := stored.Delivery()
	if delivery.Scope().Identity() != scope.Identity() || delivery.Source() != source || delivery.DeduplicationKey() != key {
		return StoredDelivery{}, false, ErrInvalidStoredDeliveryEncoding
	}
	return stored, true, nil
}

func (s *FileStore) loadPath(path string) (StoredDelivery, bool, error) {
	information, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return StoredDelivery{}, false, nil
	}
	if err != nil {
		return StoredDelivery{}, false, fmt.Errorf("%w: inspect delivery", ErrInboxStorePersistence)
	}
	if !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 || information.Size() <= 0 || information.Size() > maxEncodedStoredDeliveryBytes {
		return StoredDelivery{}, false, ErrInvalidStoredDeliveryEncoding
	}
	file, err := os.Open(path)
	if err != nil {
		return StoredDelivery{}, false, fmt.Errorf("%w: open delivery", ErrInboxStorePersistence)
	}
	openedInformation, statErr := file.Stat()
	if statErr != nil || !openedInformation.Mode().IsRegular() || !os.SameFile(information, openedInformation) {
		_ = file.Close()
		return StoredDelivery{}, false, ErrInvalidStoredDeliveryEncoding
	}
	encoded, readErr := io.ReadAll(io.LimitReader(file, maxEncodedStoredDeliveryBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return StoredDelivery{}, false, fmt.Errorf("%w: read delivery", ErrInboxStorePersistence)
	}
	stored, err := ParseStoredDelivery(encoded)
	if err != nil {
		return StoredDelivery{}, false, err
	}
	return stored, true, nil
}
func (s *FileStore) persist(path string, encoded []byte) error {
	temporary, err := os.CreateTemp(s.root, ".inbox-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: create temporary delivery", ErrInboxStorePersistence)
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: protect temporary delivery", ErrInboxStorePersistence)
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: write delivery", ErrInboxStorePersistence)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: sync delivery", ErrInboxStorePersistence)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("%w: close delivery", ErrInboxStorePersistence)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("%w: replace delivery", ErrInboxStorePersistence)
	}
	keep = true
	if err := s.syncRoot(); err != nil {
		return err
	}
	return nil
}
func (s *FileStore) syncRoot() error {
	directory, err := os.Open(s.root)
	if err != nil {
		return fmt.Errorf("%w: open root", ErrInboxStorePersistence)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return fmt.Errorf("%w: sync root", ErrInboxStorePersistence)
	}
	return nil
}
func (s *FileStore) cleanupLock() error {
	var result error
	if s.lockFile != nil {
		if err := s.lockFile.Close(); err != nil {
			result = fmt.Errorf("%w: close lock", ErrInboxStorePersistence)
		}
		s.lockFile = nil
	}
	if err := s.syncRoot(); err != nil && result == nil {
		result = err
	}
	return result
}
