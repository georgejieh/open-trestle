package scm

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

type localGitPackScope struct {
	store             *LocalGitObjectStore
	catalog           *localGitPackIndexCatalog
	physicalReadBytes int64
	decompressedBytes int64
	checksumPasses    int
	cacheBytes        int64
	cache             map[string]localGitDecodedPackObject
	cacheOrder        []string
}

func newLocalGitPackScope(store *LocalGitObjectStore, catalog *localGitPackIndexCatalog) *localGitPackScope {
	return &localGitPackScope{store: store, catalog: catalog, cache: make(map[string]localGitDecodedPackObject)}
}

func (s *LocalGitObjectStore) withScopedObjectReader(ctx context.Context, fn func(localGitObjectReader) error) error {
	if s == nil || s.objectsRoot == nil {
		return fmt.Errorf("local Git object store is nil")
	}
	if s.Profile() == LocalGitObjectStoreProfileLooseOnly {
		return fn(s)
	}
	return s.withPackScope(ctx, func(scope *localGitPackScope) error {
		return fn(scope)
	})
}

func (s *LocalGitObjectStore) withPackScope(ctx context.Context, fn func(*localGitPackScope) error) error {
	if s == nil || s.objectsRoot == nil {
		return fmt.Errorf("local Git object store is nil")
	}
	if isNilInterface(ctx) {
		return fmt.Errorf("Git pack acquisition context is nil")
	}
	if fn == nil {
		return fmt.Errorf("Git pack acquisition function is nil")
	}
	if s.Profile() != LocalGitObjectStoreProfileLooseAndPackIndexV1 {
		return fmt.Errorf("Git pack scope requires packed object store profile")
	}
	if err := s.beginPackedAcquisition(ctx); err != nil {
		return err
	}
	defer s.endPackedAcquisition()
	catalog, built, err := s.catalogForPackedScope(ctx)
	if err != nil {
		return err
	}
	scope := newLocalGitPackScope(s, catalog)
	if built {
		if err := scope.chargePhysicalRead(catalog.catalogPhysicalBytes); err != nil {
			return err
		}
		for i := 0; i < catalog.catalogChecksumPasses; i++ {
			if err := scope.chargeChecksumPass(); err != nil {
				return err
			}
		}
	}
	if err := fn(scope); err != nil {
		return err
	}
	if err := catalog.validateStableWithScope(ctx, scope); err != nil {
		return err
	}
	return ctx.Err()
}

func (s *LocalGitObjectStore) beginPackedAcquisition(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.gate == nil {
		return fmt.Errorf("Git pack acquisition gate is not initialized")
	}
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	acquiredGate := true
	defer func() {
		if acquiredGate {
			<-s.gate
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing {
		return fmt.Errorf("local Git object store is closing")
	}
	if s.active == 0 {
		s.idle = make(chan struct{})
	}
	s.active++
	acquiredGate = false
	return nil
}

func (s *LocalGitObjectStore) endPackedAcquisition() {
	s.mu.Lock()
	if s.active > 0 {
		s.active--
		if s.active == 0 {
			close(s.idle)
		}
	}
	s.mu.Unlock()
	<-s.gate
}

func (s *LocalGitObjectStore) catalogForPackedScope(ctx context.Context) (*localGitPackIndexCatalog, bool, error) {
	s.mu.Lock()
	catalog := s.catalog
	s.mu.Unlock()
	if catalog != nil {
		return catalog, false, nil
	}
	builtCatalog, err := newLocalGitPackIndexCatalog(ctx, s.objectsRoot, s.objectAlgorithm, s.packLimits)
	if err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	if s.catalog != nil {
		existing := s.catalog
		s.mu.Unlock()
		_ = builtCatalog.close()
		return existing, false, nil
	}
	if s.closed || s.closing {
		s.mu.Unlock()
		_ = builtCatalog.close()
		return nil, false, fmt.Errorf("local Git object store is closing")
	}
	s.catalog = builtCatalog
	s.mu.Unlock()
	return builtCatalog, true, nil
}

func (s *localGitPackScope) RepositoryIdentity() string {
	if s == nil || s.store == nil {
		return ""
	}
	return s.store.RepositoryIdentity()
}

func (s *localGitPackScope) ReadCommit(ctx context.Context, revision evidence.RevisionIdentity) ([]byte, error) {
	canonicalRevision, err := evidence.NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || !revisionIdentityValuesEqual(revision, canonicalRevision) {
		return nil, fmt.Errorf("revision identity is not canonical")
	}
	return s.readGitObject(ctx, canonicalRevision.Algorithm(), canonicalRevision.Digest(), "commit", maxGitCommitPayloadBytes)
}

func (s *localGitPackScope) ReadTree(ctx context.Context, algorithm evidence.RevisionAlgorithm, digest string) ([]byte, error) {
	return s.readGitObject(ctx, algorithm, digest, "tree", maxGitTreePayloadBytes)
}

func (s *localGitPackScope) ReadBlob(ctx context.Context, algorithm evidence.RevisionAlgorithm, digest string) ([]byte, error) {
	return s.readGitObject(ctx, algorithm, digest, "blob", maxGitBlobPayloadBytes)
}

func (s *localGitPackScope) readGitObject(ctx context.Context, algorithm evidence.RevisionAlgorithm, digest, expectedType string, maxPayloadBytes int64) ([]byte, error) {
	if s == nil || s.catalog == nil || s.store == nil {
		return nil, fmt.Errorf("local Git pack scope is nil")
	}
	if algorithm != s.store.objectAlgorithm || algorithm != s.catalog.algorithm {
		return nil, fmt.Errorf("Git object algorithm does not match packed store profile")
	}
	return s.store.readLooseThenPackObject(ctx, s.catalog, s, algorithm, digest, expectedType, maxPayloadBytes)
}

func (s *localGitPackScope) chargePhysicalRead(bytes int64) error {
	if s == nil || s.catalog == nil {
		return LocalGitRevisionInvalidGraph
	}
	if bytes < 0 || s.physicalReadBytes > s.catalog.limits.maxPhysicalReadBytes-bytes {
		return LocalGitRevisionResourceLimit
	}
	s.physicalReadBytes += bytes
	return nil
}

func (s *localGitPackScope) chargeDecompressedWork(bytes int64) error {
	if s == nil || s.catalog == nil {
		return LocalGitRevisionInvalidGraph
	}
	if bytes < 0 || s.decompressedBytes > s.catalog.limits.maxDecompressedWorkBytes-bytes {
		return LocalGitRevisionResourceLimit
	}
	s.decompressedBytes += bytes
	return nil
}

func (s *localGitPackScope) chargeChecksumPass() error {
	if s == nil || s.catalog == nil {
		return LocalGitRevisionInvalidGraph
	}
	if s.checksumPasses >= s.catalog.limits.maxChecksumPasses {
		return LocalGitRevisionResourceLimit
	}
	s.checksumPasses++
	return nil
}

func (s *localGitPackScope) cacheGet(ref localGitPackObjectRef) (localGitDecodedPackObject, bool, error) {
	if s == nil || s.cache == nil {
		return localGitDecodedPackObject{}, false, nil
	}
	value, ok := s.cache[localGitPackCacheKey(ref)]
	if !ok {
		return localGitDecodedPackObject{}, false, nil
	}
	if err := s.chargeDecompressedWork(int64(len(value.payload))); err != nil {
		return localGitDecodedPackObject{}, false, err
	}
	return localGitDecodedPackObject{objectType: value.objectType, payload: append([]byte{}, value.payload...)}, true, nil
}

func (s *localGitPackScope) cachePut(ref localGitPackObjectRef, value localGitDecodedPackObject) error {
	if s == nil || s.catalog == nil || s.cache == nil || len(value.payload) == 0 {
		return nil
	}
	entryBytes := int64(len(value.payload))
	limits := s.catalog.limits
	if entryBytes > limits.maxBaseCacheBytes || limits.maxBaseCacheEntries <= 0 {
		return nil
	}
	key := localGitPackCacheKey(ref)
	if old, ok := s.cache[key]; ok {
		s.cacheBytes -= int64(len(old.payload))
		delete(s.cache, key)
		s.removeCacheOrder(key)
	}
	for (len(s.cacheOrder) >= limits.maxBaseCacheEntries || s.cacheBytes > limits.maxBaseCacheBytes-entryBytes) && len(s.cacheOrder) > 0 {
		evict := s.cacheOrder[0]
		s.cacheOrder = s.cacheOrder[1:]
		if old, ok := s.cache[evict]; ok {
			s.cacheBytes -= int64(len(old.payload))
			delete(s.cache, evict)
		}
	}
	if len(s.cacheOrder) >= limits.maxBaseCacheEntries || s.cacheBytes > limits.maxBaseCacheBytes-entryBytes {
		return nil
	}
	if err := s.chargeDecompressedWork(entryBytes); err != nil {
		return err
	}
	s.cache[key] = localGitDecodedPackObject{objectType: value.objectType, payload: append([]byte{}, value.payload...)}
	s.cacheOrder = append(s.cacheOrder, key)
	s.cacheBytes += entryBytes
	return nil
}

func (s *localGitPackScope) removeCacheOrder(key string) {
	for i, existing := range s.cacheOrder {
		if existing == key {
			copy(s.cacheOrder[i:], s.cacheOrder[i+1:])
			s.cacheOrder = s.cacheOrder[:len(s.cacheOrder)-1]
			return
		}
	}
}

func localGitPackCacheKey(ref localGitPackObjectRef) string {
	if ref.pack == nil {
		return ""
	}
	return ref.pack.stem + ":" + fmt.Sprintf("%d", ref.offset)
}

func isGenuineLooseAbsence(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}
