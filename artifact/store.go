package artifact

import (
	"context"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/filelock"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	maxStoreArtifacts  = 10000
	artifactFileSuffix = ".artifact.json"
	artifactLockName   = ".artifact-writer.lock"
	deletionFileSuffix = ".artifact-deleted.json"
)

var (
	// ErrInvalidStore identifies missing or unsafe store configuration.
	ErrInvalidStore = errors.New("invalid artifact store")
	// ErrInvalidStoreContext identifies a nil operation context.
	ErrInvalidStoreContext = errors.New("invalid artifact store context")
	// ErrStoreContextDone identifies a canceled store operation.
	ErrStoreContextDone = errors.New("artifact store context done")
	// ErrArtifactNotFound identifies an identity absent from the exact review scope.
	ErrArtifactNotFound = errors.New("runtime artifact not found")
	// ErrArtifactExpired identifies data beyond its immutable retention time.
	ErrArtifactExpired = errors.New("runtime artifact expired")
	// ErrStoreProtectionMismatch identifies data requiring another at-rest protection adapter.
	ErrStoreProtectionMismatch = errors.New("artifact store protection mismatch")
	// ErrStoreLocked identifies a root currently owned by another writer.
	ErrStoreLocked = errors.New("artifact store locked")
	// ErrStoreClosed identifies use after releasing the writer lock.
	ErrStoreClosed = errors.New("artifact store closed")
	// ErrStoreCapacity identifies a store beyond its local object bound.
	ErrStoreCapacity = errors.New("artifact store capacity exceeded")
	// ErrInvalidStoreRoot identifies an empty, replaced, symlinked, or unsafe root.
	ErrInvalidStoreRoot = errors.New("invalid artifact store root")
	// ErrCorruptArtifact identifies malformed or cross-wired persisted bytes.
	ErrCorruptArtifact = errors.New("corrupt runtime artifact")
	// ErrStorePersistence identifies a failed durable filesystem operation.
	ErrStorePersistence = errors.New("artifact store persistence failure")
)

// Store persists immutable scoped runtime artifacts.
type Store interface {
	Put(context.Context, Artifact, time.Time) (bool, error)
	Get(context.Context, audit.ReviewScope, string, time.Time) (Artifact, error)
}

// RetentionStore adds authorized physical deletion to artifact storage.
type RetentionStore interface {
	Store
	Delete(context.Context, DeletionAuthorization, time.Time) (DeletionReceipt, error)
}

// MemoryStore is a bounded concurrency-safe artifact store.
type MemoryStore struct {
	mu         sync.RWMutex
	protection Protection
	maximum    int
	values     map[string]Artifact
	deletions  map[string]DeletionReceipt
}

func NewMemoryStore(protection Protection, maximum int) (*MemoryStore, error) {
	if protection.String() == "" || maximum <= 0 || maximum > maxStoreArtifacts {
		return nil, ErrInvalidStore
	}
	return &MemoryStore{protection: protection, maximum: maximum, values: make(map[string]Artifact), deletions: make(map[string]DeletionReceipt)}, nil
}
func (s *MemoryStore) Put(ctx context.Context, value Artifact, at time.Time) (bool, error) {
	if err := validatePut(ctx, value, at); err != nil {
		return false, err
	}
	if s == nil {
		return false, ErrInvalidStore
	}
	if value.Protection() != s.protection {
		return false, ErrStoreProtectionMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeKey(value.Scope(), value.Identity())
	if _, deleted := s.deletions[key]; deleted {
		return false, ErrArtifactDeleted
	}
	if _, found := s.values[key]; found {
		return false, nil
	}
	if len(s.values)+len(s.deletions) >= s.maximum {
		return false, ErrStoreCapacity
	}
	s.values[key] = value
	return true, nil
}
func (s *MemoryStore) Get(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) (Artifact, error) {
	if err := validateGet(ctx, scope, identity, at); err != nil {
		return Artifact{}, err
	}
	if s == nil {
		return Artifact{}, ErrInvalidStore
	}
	s.mu.RLock()
	value, found := s.values[storeKey(scope, identity)]
	s.mu.RUnlock()
	if !found {
		return Artifact{}, ErrArtifactNotFound
	}
	if at.UnixMilli() >= value.expiresAtMillis {
		return Artifact{}, ErrArtifactExpired
	}
	return value, nil
}

func (s *MemoryStore) Delete(ctx context.Context, authorization DeletionAuthorization, at time.Time) (DeletionReceipt, error) {
	if err := validateContext(ctx); err != nil {
		return DeletionReceipt{}, err
	}
	if authorization.Validate() != nil {
		return DeletionReceipt{}, ErrInvalidDeletionAuthorization
	}
	if s == nil {
		return DeletionReceipt{}, ErrInvalidStore
	}
	key := storeKey(authorization.Scope(), authorization.ArtifactIdentity())
	s.mu.Lock()
	defer s.mu.Unlock()
	if receipt, found := s.deletions[key]; found {
		if receipt.AuthorizationIdentity() == authorization.Identity() {
			return receipt, nil
		}
		return DeletionReceipt{}, ErrArtifactDeleted
	}
	value, found := s.values[key]
	if !found {
		return DeletionReceipt{}, ErrArtifactNotFound
	}
	if !authorization.Allows(value, at) {
		return DeletionReceipt{}, ErrDeletionNotAllowed
	}
	receipt := newDeletionReceipt(value, authorization, at)
	delete(s.values, key)
	s.deletions[key] = receipt
	return receipt, nil
}

// FileStore is a private exclusive-writer local artifact store.
type FileStore struct {
	mu       sync.Mutex
	root     string
	rootInfo os.FileInfo
	lock     *filelock.Lock
	closed   bool
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
		return nil, ErrStorePersistence
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return nil, ErrStorePersistence
	}
	information, err := os.Lstat(absolute)
	if err != nil || !information.IsDir() || information.Mode().Perm() != 0o700 {
		return nil, ErrInvalidStoreRoot
	}
	lock, err := filelock.Acquire(filepath.Join(absolute, artifactLockName))
	if errors.Is(err, filelock.ErrLocked) {
		return nil, ErrStoreLocked
	}
	if err != nil {
		return nil, ErrStorePersistence
	}
	store := &FileStore{root: absolute, rootInfo: information, lock: lock}
	if err := store.syncRoot(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	if err := store.recoverDeletions(); err != nil {
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
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStorePersistence, err)
	}
	return nil
}
func (s *FileStore) Put(ctx context.Context, value Artifact, at time.Time) (bool, error) {
	if err := validatePut(ctx, value, at); err != nil {
		return false, err
	}
	if value.Protection() != ProtectionProcessPrivate {
		return false, ErrStoreProtectionMismatch
	}
	encoded, err := Encode(value)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return false, err
	}
	destination := s.artifactPath(value.Scope(), value.Identity())
	if _, _, found, deletionErr := s.loadDeletionExpected(s.deletionPath(value.Scope(), value.Identity()), value.Scope(), value.Identity()); deletionErr != nil {
		return false, deletionErr
	} else if found {
		return false, ErrArtifactDeleted
	}
	existing, found, err := s.load(destination, value.Scope(), value.Identity())
	if err != nil {
		return false, err
	}
	if found {
		if existing.Identity() != value.Identity() {
			return false, ErrCorruptArtifact
		}
		return false, nil
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return false, ErrStorePersistence
	}
	count := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			count++
		}
	}
	if count >= maxStoreArtifacts {
		return false, ErrStoreCapacity
	}
	if err := s.persist(destination, encoded); err != nil {
		return false, err
	}
	return true, nil
}
func (s *FileStore) Get(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) (Artifact, error) {
	if err := validateGet(ctx, scope, identity, at); err != nil {
		return Artifact{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return Artifact{}, err
	}
	value, found, err := s.load(s.artifactPath(scope, identity), scope, identity)
	if err != nil {
		return Artifact{}, err
	}
	if !found {
		return Artifact{}, ErrArtifactNotFound
	}
	if at.UnixMilli() >= value.expiresAtMillis {
		return Artifact{}, ErrArtifactExpired
	}
	return value, nil
}
func (s *FileStore) artifactPath(scope audit.ReviewScope, identity string) string {
	return filepath.Join(s.root, scope.Identity()+"-"+identity+artifactFileSuffix)
}
func (s *FileStore) deletionPath(scope audit.ReviewScope, identity string) string {
	return filepath.Join(s.root, scope.Identity()+"-"+identity+deletionFileSuffix)
}
func (s *FileStore) Delete(ctx context.Context, authorization DeletionAuthorization, at time.Time) (DeletionReceipt, error) {
	if err := validateContext(ctx); err != nil {
		return DeletionReceipt{}, err
	}
	if authorization.Validate() != nil {
		return DeletionReceipt{}, ErrInvalidDeletionAuthorization
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		return DeletionReceipt{}, err
	}
	deletionPath := s.deletionPath(authorization.Scope(), authorization.ArtifactIdentity())
	if receipt, completed, found, err := s.loadDeletionExpected(deletionPath, authorization.Scope(), authorization.ArtifactIdentity()); err != nil {
		return DeletionReceipt{}, err
	} else if found {
		if !completed {
			if err := s.completeDeletion(receipt, deletionPath); err != nil {
				return DeletionReceipt{}, err
			}
		}
		if receipt.AuthorizationIdentity() != authorization.Identity() {
			return DeletionReceipt{}, ErrArtifactDeleted
		}
		return receipt, nil
	}
	value, found, err := s.load(s.artifactPath(authorization.Scope(), authorization.ArtifactIdentity()), authorization.Scope(), authorization.ArtifactIdentity())
	if err != nil {
		return DeletionReceipt{}, err
	}
	if !found {
		return DeletionReceipt{}, ErrArtifactNotFound
	}
	if !authorization.Allows(value, at) {
		return DeletionReceipt{}, ErrDeletionNotAllowed
	}
	receipt := newDeletionReceipt(value, authorization, at)
	prepared, _ := encodeDeletionRecord(receipt, false)
	if err := s.persist(deletionPath, prepared); err != nil {
		return DeletionReceipt{}, err
	}
	if err := s.completeDeletion(receipt, deletionPath); err != nil {
		return DeletionReceipt{}, err
	}
	return receipt, nil
}
func (s *FileStore) completeDeletion(receipt DeletionReceipt, deletionPath string) error {
	artifactPath := s.artifactPath(receipt.Scope(), receipt.ArtifactIdentity())
	if value, found, err := s.load(artifactPath, receipt.Scope(), receipt.ArtifactIdentity()); err != nil {
		return err
	} else if found {
		if value.PayloadDigest() != receipt.PayloadDigest() {
			return ErrCorruptArtifact
		}
		if err := os.Remove(artifactPath); err != nil {
			return ErrStorePersistence
		}
		if err := s.syncRoot(); err != nil {
			return err
		}
	}
	completed, _ := encodeDeletionRecord(receipt, true)
	return s.persist(deletionPath, completed)
}
func (s *FileStore) loadDeletionExpected(filePath string, scope audit.ReviewScope, identity string) (DeletionReceipt, bool, bool, error) {
	receipt, completed, found, err := s.loadDeletion(filePath)
	if err != nil || !found {
		return receipt, completed, found, err
	}
	if receipt.Scope().Identity() != scope.Identity() || receipt.ArtifactIdentity() != identity {
		return DeletionReceipt{}, false, false, ErrCorruptArtifact
	}
	return receipt, completed, true, nil
}

func (s *FileStore) loadDeletion(filePath string) (DeletionReceipt, bool, bool, error) {
	information, err := os.Lstat(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return DeletionReceipt{}, false, false, nil
	}
	if err != nil {
		return DeletionReceipt{}, false, false, ErrStorePersistence
	}
	if !information.Mode().IsRegular() || information.Mode().Perm() != 0o600 || information.Size() <= 0 || information.Size() > maxEncodedDeletionRecordBytes {
		return DeletionReceipt{}, false, false, ErrCorruptArtifact
	}
	file, err := os.Open(filePath)
	if err != nil {
		return DeletionReceipt{}, false, false, ErrStorePersistence
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(information, opened) {
		_ = file.Close()
		return DeletionReceipt{}, false, false, ErrCorruptArtifact
	}
	encoded, readErr := io.ReadAll(io.LimitReader(file, maxEncodedDeletionRecordBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return DeletionReceipt{}, false, false, ErrStorePersistence
	}
	receipt, completed, err := parseDeletionRecord(encoded)
	if err != nil {
		return DeletionReceipt{}, false, false, ErrCorruptArtifact
	}
	return receipt, completed, true, nil
}
func (s *FileStore) recoverDeletions() error {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return ErrStorePersistence
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), deletionFileSuffix) {
			continue
		}
		path := filepath.Join(s.root, entry.Name())
		receipt, completed, found, err := s.loadDeletion(path)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if path != s.deletionPath(receipt.Scope(), receipt.ArtifactIdentity()) {
			return ErrCorruptArtifact
		}
		artifactPath := s.artifactPath(receipt.Scope(), receipt.ArtifactIdentity())
		_, artifactErr := os.Lstat(artifactPath)
		if artifactErr != nil && !errors.Is(artifactErr, os.ErrNotExist) {
			return ErrStorePersistence
		}
		if !completed || artifactErr == nil {
			if err := s.completeDeletion(receipt, path); err != nil {
				return err
			}
		}
	}
	return nil
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
func (s *FileStore) load(filePath string, scope audit.ReviewScope, identity string) (Artifact, bool, error) {
	information, err := os.Lstat(filePath)
	if errors.Is(err, os.ErrNotExist) {
		return Artifact{}, false, nil
	}
	if err != nil {
		return Artifact{}, false, ErrStorePersistence
	}
	if !information.Mode().IsRegular() || information.Mode().Perm() != 0o600 || information.Size() <= 0 || information.Size() > maxEncodedArtifactBytes {
		return Artifact{}, false, ErrCorruptArtifact
	}
	file, err := os.Open(filePath)
	if err != nil {
		return Artifact{}, false, ErrStorePersistence
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(information, opened) {
		_ = file.Close()
		return Artifact{}, false, ErrCorruptArtifact
	}
	encoded, readErr := io.ReadAll(io.LimitReader(file, maxEncodedArtifactBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return Artifact{}, false, ErrStorePersistence
	}
	value, err := Parse(encoded)
	if err != nil || value.Scope().Identity() != scope.Identity() || value.Identity() != identity {
		return Artifact{}, false, ErrCorruptArtifact
	}
	return value, true, nil
}
func (s *FileStore) persist(destination string, encoded []byte) error {
	temporary, err := os.CreateTemp(s.root, ".artifact-*.tmp")
	if err != nil {
		return ErrStorePersistence
	}
	path := temporary.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(path)
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
	if err := os.Rename(path, destination); err != nil {
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
func validatePut(ctx context.Context, value Artifact, at time.Time) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if value.Validate() != nil {
		return ErrInvalidArtifact
	}
	atMillis := at.UnixMilli()
	if atMillis < value.createdAtMillis || atMillis >= value.expiresAtMillis {
		return ErrArtifactExpired
	}
	return nil
}
func validateGet(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) error {
	if err := validateContext(ctx); err != nil {
		return err
	}
	if scope.Validate() != nil || !validDigest(identity) || at.UnixMilli() <= 0 || at.UnixMilli() > maxArtifactUnixMilliseconds {
		return ErrInvalidStore
	}
	return nil
}
func validateContext(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidStoreContext
	}
	if ctx.Err() != nil {
		return ErrStoreContextDone
	}
	return nil
}
func storeKey(scope audit.ReviewScope, identity string) string {
	return scope.Identity() + ":" + identity
}
