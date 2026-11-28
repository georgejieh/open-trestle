package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/filelock"
)

const (
	maxStoreArtifacts  = 10000
	artifactFileSuffix = ".artifact.json"
	artifactLockName   = ".artifact-writer.lock"
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

// MemoryStore is a bounded concurrency-safe artifact store.
type MemoryStore struct {
	mu         sync.RWMutex
	protection Protection
	maximum    int
	values     map[string]Artifact
}

func NewMemoryStore(protection Protection, maximum int) (*MemoryStore, error) {
	if protection.String() == "" || maximum <= 0 || maximum > maxStoreArtifacts {
		return nil, ErrInvalidStore
	}
	return &MemoryStore{protection: protection, maximum: maximum, values: make(map[string]Artifact)}, nil
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
	if _, found := s.values[key]; found {
		return false, nil
	}
	if len(s.values) >= s.maximum {
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

// FileStore uses private paths and a cooperative exclusive writer lease.
// Normal operations are path-based; startup root checks do not pin their lifetime.
type FileStore struct {
	mu                 sync.Mutex
	root               string
	rootInfo           os.FileInfo
	lock               *filelock.Lock
	closed             bool
	afterPersistRename func() error
}

// PendingFileStore holds an exclusive writer lock until it is activated or closed.
// Activation does not validate ownership of historical artifacts.
type PendingFileStore struct {
	state *pendingFileStoreState
}

type pendingFileStoreState struct {
	mu    sync.Mutex
	store *FileStore
	// Test-only observers are installed before concurrent use and never mutated.
	onLeaseMethodContended func()
	onOwnedRootPostcheck   func(pinErr, openedErr, leafErr error)
}

// OpenPendingFileStore prepares a root and locks it.
// Root creation, permissions, lock acquisition, and root sync still take effect.
func OpenPendingFileStore(root string) (*PendingFileStore, error) {
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
		return nil, errors.Join(err, store.Close())
	}
	return &PendingFileStore{state: &pendingFileStoreState{store: store}}, nil
}

// WithOwnedRoot borrows the constructor-held artifact root while the pending
// writer lease cannot be activated or closed. The callback must not retain the
// root or call Activate, Close, or another pending operation.
// This is cooperative path consistency evidence, not hostile swap resistance.
func (p *PendingFileStore) WithOwnedRoot(use func(*os.Root) error) (err error) {
	if p == nil {
		return ErrInvalidStore
	}
	if p.state == nil {
		return ErrStoreClosed
	}
	if use == nil {
		return ErrInvalidStore
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	store := p.state.store
	if store == nil {
		return ErrStoreClosed
	}
	if err := store.ensureOpen(); err != nil {
		return err
	}
	pin, err := fileauthority.PinDirectory(store.root)
	if err != nil {
		return errors.Join(ErrInvalidStoreRoot, err)
	}
	if err := validatePendingRootLeaf(store.root, store.rootInfo); err != nil {
		return err
	}
	opened, err := os.OpenRoot(store.root)
	if err != nil {
		return errors.Join(ErrInvalidStoreRoot, err)
	}
	// Close before releasing state.mu on every path, including callback or
	// postcheck panic. A callback panic remains the original panic.
	defer func() {
		panicking := recover()
		closeErr := opened.Close()
		if panicking != nil {
			panic(panicking)
		}
		err = errors.Join(err, closeErr)
	}()
	if err := validatePendingOpenedRoot(opened, store.rootInfo); err != nil {
		return err
	}
	if err := validatePendingRootLeaf(store.root, store.rootInfo); err != nil {
		return err
	}
	if err := pin.Recheck(); err != nil {
		return errors.Join(ErrInvalidStoreRoot, err)
	}
	return func() (result error) {
		defer func() {
			// Postchecks run after any callback outcome, including panic. Preserve
			// the original panic if a postcheck or observer also panics.
			if panicValue := recover(); panicValue != nil {
				defer func() { panic(panicValue) }()
			}
			pinErr := pin.Recheck() // Recheck the retained pre-open chain.
			openedErr := validatePendingOpenedRoot(opened, store.rootInfo)
			leafErr := validatePendingRootLeaf(store.root, store.rootInfo)
			if pinErr != nil {
				pinErr = errors.Join(ErrInvalidStoreRoot, pinErr)
			}
			postcheckErr := errors.Join(pinErr, openedErr, leafErr)
			if p.state.onOwnedRootPostcheck != nil {
				p.state.onOwnedRootPostcheck(pinErr, openedErr, leafErr)
			}
			result = errors.Join(result, postcheckErr)
		}()
		return use(opened)
	}()
}

func validatePendingRootLeaf(path string, captured os.FileInfo) error {
	info, err := os.Lstat(path)
	if err != nil || captured == nil || info.Mode() != os.ModeDir|0700 || !fileauthority.TrustedOwner(info) || !os.SameFile(info, captured) {
		return errors.Join(ErrInvalidStoreRoot, err)
	}
	return nil
}

func validatePendingOpenedRoot(root *os.Root, captured os.FileInfo) error {
	info, err := root.Stat(".")
	if err != nil || captured == nil || info.Mode() != os.ModeDir|0700 || !fileauthority.TrustedOwner(info) || !os.SameFile(info, captured) {
		return errors.Join(ErrInvalidStoreRoot, err)
	}
	return nil
}

// Activate transfers the lock to the returned store once. It does not attest ownership.
func (p *PendingFileStore) Activate() (*FileStore, error) {
	if p == nil {
		return nil, ErrInvalidStore
	}
	if p.state == nil {
		return nil, ErrStoreClosed
	}
	if p.state.onLeaseMethodContended != nil {
		if p.state.mu.TryLock() {
			p.state.mu.Unlock()
		} else {
			p.state.onLeaseMethodContended()
		}
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.store == nil {
		return nil, ErrStoreClosed
	}
	store := p.state.store
	if err := store.ensureOpen(); err != nil {
		p.state.store = nil
		return nil, errors.Join(err, store.Close())
	}
	p.state.store = nil
	return store, nil
}

// Close releases a pending lock, or does nothing after activation.
func (p *PendingFileStore) Close() error {
	if p == nil {
		return ErrInvalidStore
	}
	if p.state == nil {
		return nil
	}
	if p.state.onLeaseMethodContended != nil {
		if p.state.mu.TryLock() {
			p.state.mu.Unlock()
		} else {
			p.state.onLeaseMethodContended()
		}
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.store == nil {
		return nil
	}
	store := p.state.store
	p.state.store = nil
	return store.Close()
}

// NewFileStore opens the store at root and activates it before returning.
func NewFileStore(root string) (*FileStore, error) {
	pending, err := OpenPendingFileStore(root)
	if err != nil {
		return nil, err
	}
	store, err := pending.Activate()
	if err != nil {
		return nil, errors.Join(err, pending.Close())
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
	return filepath.Join(s.root, artifactFileName(scope, identity))
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
	if s.afterPersistRename != nil {
		if err := s.afterPersistRename(); err != nil {
			return errors.Join(ErrStorePersistence, err)
		}
	}
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
