package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

type memoryObjectBackend struct {
	mu             sync.Mutex
	values         map[string]RemoteObject
	versions       uint64
	failDelete     bool
	deletedContent []byte
}

func newMemoryObjectBackend() *memoryObjectBackend {
	return &memoryObjectBackend{values: make(map[string]RemoteObject)}
}
func (b *memoryObjectBackend) Create(_ context.Context, key string, content []byte, digest string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, found := b.values[key]; found {
		return false, nil
	}
	b.versions++
	b.values[key] = RemoteObject{Content: append([]byte(nil), content...), Version: fmt.Sprintf("version-%d", b.versions), Digest: digest}
	return true, nil
}
func (b *memoryObjectBackend) Read(_ context.Context, key string, maximum int) (RemoteObject, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	value, found := b.values[key]
	if !found {
		return RemoteObject{}, ErrRemoteObjectNotFound
	}
	if len(value.Content) > maximum {
		return RemoteObject{}, ErrRemoteObjectTooLarge
	}
	value.Content = append([]byte(nil), value.Content...)
	return value, nil
}
func (b *memoryObjectBackend) Delete(_ context.Context, key, version string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.failDelete {
		return false, errors.New("unavailable")
	}
	value, found := b.values[key]
	if !found {
		return false, nil
	}
	if value.Version != version {
		return false, ErrRemoteObjectConflict
	}
	b.deletedContent = append([]byte(nil), value.Content...)
	delete(b.values, key)
	return true, nil
}
func (b *memoryObjectBackend) raw(key string) []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.values[key].Content...)
}

type tenantKeyProvider struct {
	mu      sync.Mutex
	tenants []string
	root    [32]byte
}

func newTenantKeyProvider() *tenantKeyProvider {
	provider := &tenantKeyProvider{}
	copy(provider.root[:], []byte("0123456789abcdef0123456789abcdef"))
	return provider
}
func (p *tenantKeyProvider) GenerateDataKey(_ context.Context, tenantID string) (EnvelopeDataKey, error) {
	digest := sha256.Sum256(append(p.root[:], tenantID...))
	wrapped := make([]byte, 32)
	for index := range wrapped {
		wrapped[index] = digest[index] ^ p.root[index]
	}
	p.mu.Lock()
	p.tenants = append(p.tenants, tenantID)
	p.mu.Unlock()
	return NewEnvelopeDataKey(digest, "kms:test:key:v1", wrapped)
}
func (p *tenantKeyProvider) UnwrapDataKey(_ context.Context, tenantID, keyReference string, wrapped []byte) ([32]byte, error) {
	p.mu.Lock()
	p.tenants = append(p.tenants, tenantID)
	p.mu.Unlock()
	if keyReference != "kms:test:key:v1" || len(wrapped) != 32 {
		return [32]byte{}, errors.New("wrong key")
	}
	digest := sha256.Sum256(append(p.root[:], tenantID...))
	for index := range wrapped {
		if wrapped[index]^p.root[index] != digest[index] {
			return [32]byte{}, errors.New("wrong tenant")
		}
	}
	return digest, nil
}
func TestEnvelopeStoreEncryptsAndScopesArtifacts(t *testing.T) {
	backend := newMemoryObjectBackend()
	keys := newTenantKeyProvider()
	store, err := NewEnvelopeStore("reviews", backend, keys)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	value := envelopeArtifactFixture(t, scope, `{"sensitive":"source text"}`)
	created, err := store.Put(context.Background(), value, time.UnixMilli(200))
	if err != nil || !created {
		t.Fatalf("put=(%v,%v)", created, err)
	}
	raw := backend.raw(store.artifactObjectKey(scope, value.Identity()))
	if len(raw) == 0 || bytes.Contains(raw, []byte("sensitive")) || bytes.Contains(raw, value.Payload()) {
		t.Fatal("remote object exposes plaintext")
	}
	loaded, err := store.Get(context.Background(), scope, value.Identity(), time.UnixMilli(201))
	if err != nil || loaded.Identity() != value.Identity() || !bytes.Equal(loaded.Payload(), value.Payload()) {
		t.Fatalf("get=(%#v,%v)", loaded, err)
	}
	created, err = store.Put(context.Background(), value, time.UnixMilli(202))
	if err != nil || created {
		t.Fatalf("repeat=(%v,%v)", created, err)
	}
	other, _ := audit.NewReviewScope("tenant-b", "repo-a", "run-a")
	if _, err := store.Get(context.Background(), other, value.Identity(), time.UnixMilli(201)); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("cross tenant err=%v", err)
	}
}
func TestEnvelopeStoreRejectsTamperedCiphertext(t *testing.T) {
	backend := newMemoryObjectBackend()
	store, _ := NewEnvelopeStore("reviews", backend, newTenantKeyProvider())
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-tamper")
	value := envelopeArtifactFixture(t, scope, `{"value":true}`)
	_, _ = store.Put(context.Background(), value, time.UnixMilli(200))
	key := store.artifactObjectKey(scope, value.Identity())
	backend.mu.Lock()
	object := backend.values[key]
	object.Content[len(object.Content)-1] ^= 0xff
	object.Digest = hashBytes(object.Content)
	backend.values[key] = object
	backend.mu.Unlock()
	if _, err := store.Get(context.Background(), scope, value.Identity(), time.UnixMilli(201)); !errors.Is(err, ErrCorruptArtifact) {
		t.Fatalf("err=%v", err)
	}
}
func TestEnvelopeStoreDeletionIsRecoverableAndIdempotent(t *testing.T) {
	backend := newMemoryObjectBackend()
	store, _ := NewEnvelopeStore("reviews", backend, newTenantKeyProvider())
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-delete")
	value := envelopeArtifactFixture(t, scope, `{"erase":true}`)
	_, _ = store.Put(context.Background(), value, time.UnixMilli(200))
	authorization := deletionAuthorizationFixture(t, scope, value.Identity(), DeletionExpired, time.UnixMilli(1000))
	backend.failDelete = true
	if _, err := store.Delete(context.Background(), authorization, time.UnixMilli(1000)); !errors.Is(err, ErrRemoteStorePersistence) {
		t.Fatalf("interrupted err=%v", err)
	}
	intent := backend.raw(store.deletionIntentObjectKey(scope, value.Identity()))
	if len(intent) == 0 {
		t.Fatal("missing durable intent")
	}
	if bytes.Contains(intent, []byte(scope.TenantID())) || bytes.Contains(intent, []byte(scope.RepositoryID())) || bytes.Contains(intent, []byte(scope.ReviewRunID())) {
		t.Fatal("remote intent exposes scope names")
	}
	backend.failDelete = false
	receipt, found, err := store.RecoverDeletion(context.Background(), scope, value.Identity())
	if err != nil || !found || receipt.AuthorizationIdentity() != authorization.Identity() {
		t.Fatalf("recover=(%#v,%v,%v)", receipt, found, err)
	}
	if len(backend.raw(store.artifactObjectKey(scope, value.Identity()))) != 0 {
		t.Fatal("artifact remains")
	}
	again, err := store.Delete(context.Background(), authorization, time.UnixMilli(1001))
	if err != nil || again.Identity() != receipt.Identity() {
		t.Fatalf("again=(%#v,%v)", again, err)
	}
	if _, err := store.Get(context.Background(), scope, value.Identity(), time.UnixMilli(1001)); !errors.Is(err, ErrArtifactDeleted) {
		t.Fatalf("get err=%v", err)
	}
	if _, err := store.Put(context.Background(), value, time.UnixMilli(201)); !errors.Is(err, ErrArtifactDeleted) {
		t.Fatalf("put err=%v", err)
	}
}
func TestEnvelopeStoreConcurrentPutIsIdempotent(t *testing.T) {
	backend := newMemoryObjectBackend()
	store, _ := NewEnvelopeStore("reviews", backend, newTenantKeyProvider())
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-race")
	value := envelopeArtifactFixture(t, scope, `{"race":true}`)
	var wait sync.WaitGroup
	results := make(chan bool, 16)
	failures := make(chan error, 16)
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			created, err := store.Put(context.Background(), value, time.UnixMilli(200))
			results <- created
			failures <- err
		}()
	}
	wait.Wait()
	close(results)
	close(failures)
	createdCount := 0
	for created := range results {
		if created {
			createdCount++
		}
	}
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	if createdCount != 1 {
		t.Fatalf("created=%d", createdCount)
	}
}
func envelopeArtifactFixture(t *testing.T, scope audit.ReviewScope, payload string) Artifact {
	t.Helper()
	value, err := New(scope, KindContextPacket, "application/json", ClassificationRestricted, OriginHost, ProtectionEnvelopeEncrypted, []string{strings.Repeat("a", 64)}, []byte(payload), time.UnixMilli(100), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type plaintextKeyProvider struct{}

func (plaintextKeyProvider) GenerateDataKey(context.Context, string) (EnvelopeDataKey, error) {
	var key [32]byte
	copy(key[:], []byte("0123456789abcdef0123456789abcdef"))
	return NewEnvelopeDataKey(key, "kms:unsafe", key[:])
}
func (plaintextKeyProvider) UnwrapDataKey(context.Context, string, string, []byte) ([32]byte, error) {
	return [32]byte{}, nil
}
func TestEnvelopeStoreRejectsUnwrappedDataKeyAsEnvelope(t *testing.T) {
	backend := newMemoryObjectBackend()
	store, _ := NewEnvelopeStore("reviews", backend, plaintextKeyProvider{})
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-key")
	value := envelopeArtifactFixture(t, scope, `{"secret":true}`)
	if _, err := store.Put(context.Background(), value, time.UnixMilli(200)); !errors.Is(err, ErrEnvelopeKeyUnavailable) && !errors.Is(err, ErrInvalidEnvelopeKey) {
		t.Fatalf("err=%v", err)
	}
	if len(backend.values) != 0 {
		t.Fatal("unsafe key material was persisted")
	}
}
func TestEnvelopeStoreRejectsProtectionMismatch(t *testing.T) {
	backend := newMemoryObjectBackend()
	store, _ := NewEnvelopeStore("reviews", backend, newTenantKeyProvider())
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-protection")
	value, err := New(scope, KindContextPacket, "application/json", ClassificationRestricted, OriginHost, ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, []byte(`{}`), time.UnixMilli(100), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), value, time.UnixMilli(200)); !errors.Is(err, ErrStoreProtectionMismatch) {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifyEnvelopeKeyProviderRoundTripClearsAndRejectsMismatch(t *testing.T) {
	provider := newTenantKeyProvider()
	if err := VerifyEnvelopeKeyProvider(context.Background(), "tenant-a", provider); err != nil {
		t.Fatal(err)
	}
	provider.mu.Lock()
	calls := append([]string(nil), provider.tenants...)
	provider.mu.Unlock()
	if len(calls) != 2 || calls[0] != "tenant-a" || calls[1] != "tenant-a" {
		t.Fatalf("calls=%v", calls)
	}
	if err := VerifyEnvelopeKeyProvider(context.Background(), "tenant-a", mismatchedEnvelopeKeyProvider{}); !errors.Is(err, ErrInvalidEnvelopeKey) {
		t.Fatalf("mismatch=%v", err)
	}
}

type mismatchedEnvelopeKeyProvider struct{}

func (mismatchedEnvelopeKeyProvider) GenerateDataKey(context.Context, string) (EnvelopeDataKey, error) {
	var key [32]byte
	for i := range key {
		key[i] = 1
	}
	return NewEnvelopeDataKey(key, "kms:test:key", []byte("wrapped-material"))
}
func (mismatchedEnvelopeKeyProvider) UnwrapDataKey(context.Context, string, string, []byte) ([32]byte, error) {
	var key [32]byte
	for i := range key {
		key[i] = 2
	}
	return key, nil
}

type partialErrorEnvelopeKeyProvider struct {
	key EnvelopeDataKey
	err error
}

func (p *partialErrorEnvelopeKeyProvider) GenerateDataKey(context.Context, string) (EnvelopeDataKey, error) {
	return p.key, p.err
}
func (*partialErrorEnvelopeKeyProvider) UnwrapDataKey(context.Context, string, string, []byte) ([32]byte, error) {
	return [32]byte{}, errors.New("unexpected unwrap")
}
func TestVerifyEnvelopeKeyProviderClearsPartialErrorOutput(t *testing.T) {
	var plaintext [32]byte
	for index := range plaintext {
		plaintext[index] = 7
	}
	wrapped := bytes.Repeat([]byte{9}, 64)
	marker := errors.New("partial provider failure")
	provider := &partialErrorEnvelopeKeyProvider{key: EnvelopeDataKey{plaintext: plaintext, keyReference: "kms:test:key", wrapped: wrapped}, err: marker}
	if err := VerifyEnvelopeKeyProvider(context.Background(), "tenant-a", provider); !errors.Is(err, marker) {
		t.Fatalf("err=%v", err)
	}
	if !allZeroBytes(wrapped) {
		t.Fatal("wrapped output retained")
	}
	key := EnvelopeDataKey{plaintext: plaintext, keyReference: "kms:test:key", wrapped: bytes.Repeat([]byte{9}, 64)}
	key.clear()
	if !allZeroBytes(key.plaintext[:]) || !allZeroBytes(key.wrapped) {
		t.Fatal("key clear left material")
	}
}
func allZeroBytes(value []byte) bool {
	for _, candidate := range value {
		if candidate != 0 {
			return false
		}
	}
	return true
}

func TestEnvelopeStoreClearsPartialKeyOutputOnPutError(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	value := envelopeArtifactFixture(t, scope, `{"public":"conformance"}`)
	var plaintext [32]byte
	for index := range plaintext {
		plaintext[index] = 7
	}
	wrapped := bytes.Repeat([]byte{9}, 64)
	marker := errors.New("partial provider failure")
	keys := &partialErrorEnvelopeKeyProvider{key: EnvelopeDataKey{plaintext: plaintext, keyReference: "kms:test:key", wrapped: wrapped}, err: marker}
	store, err := NewEnvelopeStore("reviews", newMemoryObjectBackend(), keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Put(context.Background(), value, time.UnixMilli(200)); !errors.Is(err, ErrEnvelopeKeyUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if !allZeroBytes(wrapped) {
		t.Fatal("wrapped output retained")
	}
}

func TestEnvelopeStorageAuthorityIdentityBindsExactComponents(t *testing.T) {
	backend, key := hashBytes([]byte("s3")), hashBytes([]byte("kms"))
	first, err := EnvelopeStorageAuthorityIdentity("tenant-a", backend, key, "reviews")
	if err != nil {
		t.Fatal(err)
	}
	same, _ := EnvelopeStorageAuthorityIdentity("tenant-a", backend, key, "reviews")
	changed, _ := EnvelopeStorageAuthorityIdentity("tenant-a", backend, key, "other")
	if first == "" || same != first || changed == first {
		t.Fatalf("identities=%s/%s/%s", first, same, changed)
	}
}
func TestVerifyEnvelopeStorageConformanceCreatesReadsAndDeletes(t *testing.T) {
	backend := newMemoryObjectBackend()
	store, err := NewEnvelopeStore("reviews", backend, newTenantKeyProvider())
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "setup-root-a")
	authority, _ := EnvelopeStorageAuthorityIdentity("tenant-a", hashBytes([]byte("s3")), hashBytes([]byte("kms")), "reviews")
	receipt, err := VerifyEnvelopeStorageConformance(context.Background(), store, scope, authority, time.UnixMilli(100).UTC())
	if err != nil || receipt.Validate() != nil || receipt.Identity() == "" {
		t.Fatalf("receipt=%#v err=%v", receipt, err)
	}
	if len(backend.values) != 0 {
		t.Fatalf("residue=%v", backend.values)
	}
	if bytes.Contains(backend.deletedContent, []byte(envelopeStorageConformancePayload)) || bytes.Contains(backend.deletedContent, []byte(base64.StdEncoding.EncodeToString([]byte(envelopeStorageConformancePayload)))) {
		t.Fatal("stored object exposed conformance plaintext")
	}
	if strings.Contains(fmt.Sprintf("%#v", receipt), authority) {
		t.Fatal("receipt formatter leaked authority")
	}
}
func TestVerifyEnvelopeStorageConformanceRecoversDeterministicResidue(t *testing.T) {
	backend := newMemoryObjectBackend()
	backend.failDelete = true
	store, _ := NewEnvelopeStore("reviews", backend, newTenantKeyProvider())
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "setup-root-a")
	authority, _ := EnvelopeStorageAuthorityIdentity("tenant-a", hashBytes([]byte("s3")), hashBytes([]byte("kms")), "reviews")
	if _, err := VerifyEnvelopeStorageConformance(context.Background(), store, scope, authority, time.UnixMilli(100).UTC()); !errors.Is(err, ErrRemoteStorePersistence) {
		t.Fatalf("first=%v", err)
	}
	if len(backend.values) != 1 {
		t.Fatalf("residue=%d", len(backend.values))
	}
	backend.failDelete = false
	receipt, err := VerifyEnvelopeStorageConformance(context.Background(), store, scope, authority, time.UnixMilli(100).UTC())
	if err != nil || receipt.Validate() != nil || len(backend.values) != 0 {
		t.Fatalf("retry=%#v %v residue=%d", receipt, err, len(backend.values))
	}
}

func TestEnvelopeStorePreservesDeterministicConflictAndInvalidKeyClasses(t *testing.T) {
	if err := mapRemoteReadError(ErrRemoteObjectConflict); !errors.Is(err, ErrRemoteStoreConflict) {
		t.Fatalf("conflict=%v", err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	value := envelopeArtifactFixture(t, scope, `{"public":"conformance"}`)
	var plaintext [32]byte
	for index := range plaintext {
		plaintext[index] = 7
	}
	keys := &partialErrorEnvelopeKeyProvider{key: EnvelopeDataKey{plaintext: plaintext, keyReference: "kms:test:key", wrapped: bytes.Repeat([]byte{9}, 64)}, err: ErrInvalidEnvelopeKey}
	store, _ := NewEnvelopeStore("reviews", newMemoryObjectBackend(), keys)
	if _, err := store.Put(context.Background(), value, time.UnixMilli(200)); !errors.Is(err, ErrInvalidEnvelopeKey) {
		t.Fatalf("key class=%v", err)
	}
}

func TestEnvelopeDataKeyAdmissionClearsRejectedCopy(t *testing.T) {
	var plaintext [32]byte
	for index := range plaintext {
		plaintext[index] = 7
	}
	value := &EnvelopeDataKey{plaintext: plaintext, keyReference: "invalid key reference with spaces", wrapped: bytes.Repeat([]byte{9}, 64)}
	if _, err := admitEnvelopeDataKey(value); !errors.Is(err, ErrInvalidEnvelopeKey) {
		t.Fatalf("err=%v", err)
	}
	if !allZeroBytes(value.plaintext[:]) || !allZeroBytes(value.wrapped) || value.keyReference != "" {
		t.Fatal("rejected key copy retained material")
	}
}
