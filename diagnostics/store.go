package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/filelock"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	maxStoreRecords     = 10000
	diagnosticSetSuffix = ".diagnostic-set.json"
	diagnosticLockName  = ".diagnostic-writer.lock"
)

var (
	// ErrInvalidStore identifies a missing or unusable diagnostic store.
	ErrInvalidStore = errors.New("invalid diagnostic store")
	// ErrInvalidStoreContext identifies a nil operation context.
	ErrInvalidStoreContext = errors.New("invalid diagnostic store context")
	// ErrStoreContextDone identifies a canceled store operation.
	ErrStoreContextDone = errors.New("diagnostic store context done")
	// ErrSetNotFound identifies a scope without a diagnostic set.
	ErrSetNotFound = errors.New("diagnostic set not found")
	// ErrSetConflict identifies another immutable set in the same review scope.
	ErrSetConflict = errors.New("diagnostic set conflict")
	// ErrInvalidStoreRoot identifies a missing, replaced, symlinked, or unsafe root.
	ErrInvalidStoreRoot = errors.New("invalid diagnostic store root")
	// ErrStoreLocked identifies a root already owned by a writer.
	ErrStoreLocked = errors.New("diagnostic store locked")
	// ErrStoreClosed identifies use after releasing a writer lock.
	ErrStoreClosed = errors.New("diagnostic store closed")
	// ErrStoreCapacity identifies a root beyond its record bound.
	ErrStoreCapacity = errors.New("diagnostic store capacity exceeded")
	// ErrCorruptStoreRecord identifies malformed or cross-wired persisted data.
	ErrCorruptStoreRecord = errors.New("corrupt diagnostic store record")
	// ErrStorePersistence identifies a failed durable filesystem operation.
	ErrStorePersistence = errors.New("diagnostic store persistence failure")
)

// Store persists one immutable verified diagnostic set per review scope.
type Store interface {
	PutDiagnosticSet(context.Context, Set) (bool, error)
	GetDiagnosticSet(context.Context, audit.ReviewScope) (Set, error)
}

// MemoryStore is a concurrency-safe bounded in-memory diagnostic store.
type MemoryStore struct {
	mu   sync.RWMutex
	sets map[string]Set
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{sets: make(map[string]Set)} }
func (s *MemoryStore) PutDiagnosticSet(ctx context.Context, set Set) (bool, error) {
	if err := validateStoreOperation(ctx); err != nil {
		return false, err
	}
	if s == nil {
		return false, ErrInvalidStore
	}
	if set.Validate() != nil {
		return false, ErrInvalidSet
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := set.Scope().Identity()
	if existing, found := s.sets[key]; found {
		if existing.Identity() == set.Identity() {
			return false, nil
		}
		return false, ErrSetConflict
	}
	if len(s.sets) >= maxStoreRecords {
		return false, ErrStoreCapacity
	}
	s.sets[key] = set
	return true, nil
}
func (s *MemoryStore) GetDiagnosticSet(ctx context.Context, scope audit.ReviewScope) (Set, error) {
	if err := validateStoreRead(ctx, scope); err != nil {
		return Set{}, err
	}
	if s == nil {
		return Set{}, ErrInvalidStore
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	set, found := s.sets[scope.Identity()]
	if !found {
		return Set{}, ErrSetNotFound
	}
	return set, nil
}

// FileStore is an exclusive-writer crash-safe local diagnostic store.
type FileStore struct {
	mu             sync.Mutex
	root, lockPath string
	rootInfo       os.FileInfo
	lock           *filelock.Lock
	closed         bool
}

func NewFileStore(root string) (*FileStore, error) {
	if root == "" {
		return nil, ErrInvalidStoreRoot
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, ErrInvalidStoreRoot
	}
	if information, statErr := os.Lstat(absolute); statErr == nil && information.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidStoreRoot
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return nil, ErrInvalidStoreRoot
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("%w: create root", ErrStorePersistence)
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return nil, fmt.Errorf("%w: protect root", ErrStorePersistence)
	}
	information, err := os.Lstat(absolute)
	if err != nil || !information.IsDir() || information.Mode().Perm() != 0o700 {
		return nil, ErrInvalidStoreRoot
	}
	lockPath := filepath.Join(absolute, diagnosticLockName)
	lock, err := filelock.Acquire(lockPath)
	if errors.Is(err, filelock.ErrLocked) {
		return nil, ErrStoreLocked
	}
	if err != nil {
		return nil, fmt.Errorf("%w: acquire lock", ErrStorePersistence)
	}
	store := &FileStore{root: absolute, lockPath: lockPath, rootInfo: information, lock: lock}
	if err := store.syncRoot(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return store, nil
}
func (s *FileStore) Close() error {
	if s == nil {
		return ErrInvalidStore
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}
func (s *FileStore) PutDiagnosticSet(ctx context.Context, set Set) (bool, error) {
	if err := validateStoreOperation(ctx); err != nil {
		return false, err
	}
	if set.Validate() != nil {
		return false, ErrInvalidSet
	}
	encoded, err := EncodeSet(set)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return false, err
	}
	path := s.setPath(set.Scope())
	existing, found, err := s.load(path, set.Scope())
	if err != nil {
		return false, err
	}
	if found {
		if existing.Identity() == set.Identity() {
			return false, nil
		}
		return false, ErrSetConflict
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return false, fmt.Errorf("%w: read root", ErrStorePersistence)
	}
	count := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			count++
		}
	}
	if count >= maxStoreRecords {
		return false, ErrStoreCapacity
	}
	if err := s.persist(path, encoded); err != nil {
		return false, err
	}
	return true, nil
}
func (s *FileStore) GetDiagnosticSet(ctx context.Context, scope audit.ReviewScope) (Set, error) {
	if err := validateStoreRead(ctx, scope); err != nil {
		return Set{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return Set{}, err
	}
	set, found, err := s.load(s.setPath(scope), scope)
	if err != nil {
		return Set{}, err
	}
	if !found {
		return Set{}, ErrSetNotFound
	}
	return set, nil
}
func (s *FileStore) setPath(scope audit.ReviewScope) string {
	return filepath.Join(s.root, scope.Identity()+diagnosticSetSuffix)
}
func (s *FileStore) ensureOpen() error {
	if s == nil {
		return ErrInvalidStore
	}
	if s.closed || s.lock == nil {
		return ErrStoreClosed
	}
	information, err := os.Lstat(s.root)
	if err != nil || !information.IsDir() || information.Mode()&os.ModeSymlink != 0 || information.Mode().Perm() != 0o700 || !os.SameFile(information, s.rootInfo) {
		return ErrInvalidStoreRoot
	}
	return nil
}
func (s *FileStore) load(filePath string, scope audit.ReviewScope) (Set, bool, error) {
	information, err := os.Lstat(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return Set{}, false, nil
	}
	if err != nil {
		return Set{}, false, fmt.Errorf("%w: inspect record", ErrStorePersistence)
	}
	if !information.Mode().IsRegular() || information.Mode().Perm() != 0o600 || information.Size() <= 0 || information.Size() > maxEncodedSetBytes {
		return Set{}, false, ErrCorruptStoreRecord
	}
	file, err := os.Open(filePath)
	if err != nil {
		return Set{}, false, fmt.Errorf("%w: open record", ErrStorePersistence)
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(information, opened) {
		_ = file.Close()
		return Set{}, false, ErrCorruptStoreRecord
	}
	encoded, readErr := io.ReadAll(io.LimitReader(file, maxEncodedSetBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return Set{}, false, fmt.Errorf("%w: read record", ErrStorePersistence)
	}
	set, err := ParseSet(encoded)
	if err != nil || set.Scope().Identity() != scope.Identity() {
		return Set{}, false, ErrCorruptStoreRecord
	}
	return set, true, nil
}
func (s *FileStore) persist(destination string, encoded []byte) error {
	temporary, err := os.CreateTemp(s.root, ".diagnostic-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: create temporary", ErrStorePersistence)
	}
	temporaryPath := temporary.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return ErrStorePersistence
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return ErrStorePersistence
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return ErrStorePersistence
	}
	if err := temporary.Close(); err != nil {
		return ErrStorePersistence
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return ErrStorePersistence
	}
	renamed = true
	return s.syncRoot()
}
func (s *FileStore) syncRoot() error {
	directory, err := os.Open(s.root)
	if err != nil {
		return ErrStorePersistence
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return ErrStorePersistence
	}
	return nil
}
func validateStoreOperation(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidStoreContext
	}
	if ctx.Err() != nil {
		return ErrStoreContextDone
	}
	return nil
}
func validateStoreRead(ctx context.Context, scope audit.ReviewScope) error {
	if err := validateStoreOperation(ctx); err != nil {
		return err
	}
	if scope.Validate() != nil {
		return ErrInvalidSet
	}
	return nil
}
