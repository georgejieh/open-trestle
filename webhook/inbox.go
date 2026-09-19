package webhook

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"
)

const (
	maxVerifierAuthorities = 1024
	maxInboxListLimit      = 100
	maxMemoryStoreEntries  = 1024
)

var (
	// ErrInvalidAdmissionPolicy identifies empty, duplicate, or malformed verifier authority.
	ErrInvalidAdmissionPolicy = errors.New("invalid webhook admission policy")
	// ErrVerifierNotAuthorized identifies verified input outside configured scope authority.
	ErrVerifierNotAuthorized = errors.New("webhook verifier not authorized")
	// ErrInvalidInbox identifies a missing store or admission policy.
	ErrInvalidInbox = errors.New("invalid webhook inbox")
	// ErrInvalidInboxContext identifies a nil operation context.
	ErrInvalidInboxContext = errors.New("invalid webhook inbox context")
	// ErrInboxContextDone identifies a canceled inbox operation.
	ErrInboxContextDone = errors.New("webhook inbox context done")
	// ErrInvalidAcceptanceTime identifies acknowledgment before receipt or outside bounds.
	ErrInvalidAcceptanceTime = errors.New("invalid webhook acceptance time")
	// ErrInboxStoreCapacity identifies an inbox beyond its configured record bound.
	ErrInboxStoreCapacity = errors.New("webhook inbox store capacity exceeded")
	// ErrDeliveryConflict identifies reuse of one forge delivery ID for different content.
	ErrDeliveryConflict = errors.New("webhook delivery conflict")
	// ErrDeliveryExpired identifies a retired delivery whose body must not be replayed.
	ErrDeliveryExpired = errors.New("webhook delivery expired")
	// ErrInvalidInboxList identifies an unsafe scope, source, cursor, or page bound.
	ErrInvalidInboxList = errors.New("invalid webhook inbox list")
	// ErrInvalidAcceptanceReceipt identifies malformed durable acknowledgment metadata.
	ErrInvalidAcceptanceReceipt = errors.New("invalid webhook acceptance receipt")
	// ErrInvalidAcceptanceReceiptIdentity identifies receipt content inconsistent with its identity.
	ErrInvalidAcceptanceReceiptIdentity = errors.New("invalid webhook acceptance receipt identity")
)

// VerifierAuthority approves one exact verifier for a repository and source protocol.
type VerifierAuthority struct {
	Scope            RepositoryScope
	Source           Source
	VerifierIdentity string
}

// AdmissionPolicy is an immutable exact verifier allowlist.
type AdmissionPolicy struct{ authorities map[string]string }

func NewAdmissionPolicy(authorities []VerifierAuthority) (AdmissionPolicy, error) {
	if len(authorities) == 0 || len(authorities) > maxVerifierAuthorities {
		return AdmissionPolicy{}, ErrInvalidAdmissionPolicy
	}
	values := make(map[string]string, len(authorities))
	for _, authority := range authorities {
		if authority.Scope.Validate() != nil || authority.Source.Validate() != nil || !validWebhookDigest(authority.VerifierIdentity) {
			return AdmissionPolicy{}, ErrInvalidAdmissionPolicy
		}
		key := authorityKey(authority.Scope, authority.Source)
		if _, exists := values[key]; exists {
			return AdmissionPolicy{}, ErrInvalidAdmissionPolicy
		}
		values[key] = authority.VerifierIdentity
	}
	return AdmissionPolicy{authorities: values}, nil
}
func (p AdmissionPolicy) Allows(delivery VerifiedDelivery) bool {
	if delivery.Validate() != nil {
		return false
	}
	return p.authorities[authorityKey(delivery.Scope(), delivery.Source())] == delivery.VerifierIdentity()
}
func (p AdmissionPolicy) Validate() error {
	if len(p.authorities) == 0 || len(p.authorities) > maxVerifierAuthorities {
		return ErrInvalidAdmissionPolicy
	}
	for key, value := range p.authorities {
		if key == "" || !validWebhookDigest(value) {
			return ErrInvalidAdmissionPolicy
		}
	}
	return nil
}
func authorityKey(scope RepositoryScope, source Source) string {
	return scope.Identity() + ":" + source.String()
}

// AcceptanceReceipt proves that exact verified payload metadata reached the store.
type AcceptanceReceipt struct {
	identity, deliveryIdentity, deduplicationKey string
	scope                                        RepositoryScope
	source                                       Source
	acceptedAtMillis                             int64
}

func newAcceptanceReceipt(delivery VerifiedDelivery, at time.Time) (AcceptanceReceipt, error) {
	atMillis := at.UnixMilli()
	if atMillis < delivery.receivedAtMillis || atMillis > maxWebhookUnixMilliseconds {
		return AcceptanceReceipt{}, ErrInvalidAcceptanceTime
	}
	receipt := AcceptanceReceipt{deliveryIdentity: delivery.Identity(), deduplicationKey: delivery.DeduplicationKey(), scope: delivery.Scope(), source: delivery.Source(), acceptedAtMillis: atMillis}
	receipt.identity = deriveAcceptanceIdentity(receipt)
	return receipt, nil
}
func (r AcceptanceReceipt) Identity() string         { return r.identity }
func (r AcceptanceReceipt) DeliveryIdentity() string { return r.deliveryIdentity }
func (r AcceptanceReceipt) DeduplicationKey() string { return r.deduplicationKey }
func (r AcceptanceReceipt) Scope() RepositoryScope   { return r.scope }
func (r AcceptanceReceipt) Source() Source           { return r.source }
func (r AcceptanceReceipt) AcceptedAt() time.Time    { return time.UnixMilli(r.acceptedAtMillis).UTC() }
func (r AcceptanceReceipt) Validate() error {
	validIdentities := validWebhookDigest(r.deliveryIdentity) && validWebhookDigest(r.deduplicationKey)
	validScope := r.scope.Validate() == nil && r.source.Validate() == nil
	validTime := r.acceptedAtMillis > 0 && r.acceptedAtMillis <= maxWebhookUnixMilliseconds
	if !validIdentities || !validScope || !validTime {
		return ErrInvalidAcceptanceReceipt
	}
	if r.identity != deriveAcceptanceIdentity(r) {
		return ErrInvalidAcceptanceReceiptIdentity
	}
	return nil
}
func (r AcceptanceReceipt) String() string   { return "webhook acceptance receipt" }
func (r AcceptanceReceipt) GoString() string { return "webhook.AcceptanceReceipt{<redacted>}" }
func (r AcceptanceReceipt) Format(state fmt.State, verb rune) {
	formatted := "webhook acceptance receipt"
	if verb == 'q' {
		formatted = `"webhook acceptance receipt"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "webhook.AcceptanceReceipt{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}
func deriveAcceptanceIdentity(receipt AcceptanceReceipt) string {
	return hashWebhookValue(struct {
		DeliveryIdentity       string `json:"delivery_identity"`
		DeduplicationKey       string `json:"deduplication_key"`
		ScopeIdentity          string `json:"scope_identity"`
		Source                 string `json:"source"`
		AcceptedAtMilliseconds int64  `json:"accepted_at_milliseconds"`
	}{receipt.deliveryIdentity, receipt.deduplicationKey, receipt.scope.Identity(), receipt.source.String(), receipt.acceptedAtMillis})
}

// StoredDelivery is immutable accepted payload and acknowledgment metadata.
type StoredDelivery struct {
	delivery VerifiedDelivery
	receipt  AcceptanceReceipt
}

// NewStoredDelivery binds one verified delivery to its durable acceptance time.
func NewStoredDelivery(delivery VerifiedDelivery, at time.Time) (StoredDelivery, error) {
	receipt, err := newAcceptanceReceipt(delivery, at)
	if err != nil {
		return StoredDelivery{}, err
	}
	stored := StoredDelivery{delivery: delivery, receipt: receipt}
	if err := stored.Validate(); err != nil {
		return StoredDelivery{}, err
	}
	return stored, nil
}

func (s StoredDelivery) Delivery() VerifiedDelivery { return s.delivery }
func (s StoredDelivery) Receipt() AcceptanceReceipt { return s.receipt }
func (s StoredDelivery) Validate() error {
	if s.delivery.Validate() != nil || s.receipt.Validate() != nil || s.receipt.DeliveryIdentity() != s.delivery.Identity() || s.receipt.DeduplicationKey() != s.delivery.DeduplicationKey() {
		return ErrInvalidAcceptanceReceipt
	}
	return nil
}

// Store durably deduplicates exact deliveries.
type Store interface {
	Put(context.Context, VerifiedDelivery, time.Time) (StoredDelivery, bool, error)
	Get(context.Context, RepositoryScope, Source, string) (StoredDelivery, bool, error)
	List(context.Context, RepositoryScope, Source, string, int) ([]StoredDelivery, error)
}

// Inbox applies verifier authority before any store operation.
type Inbox struct {
	store  Store
	policy AdmissionPolicy
}

func NewInbox(store Store, policy AdmissionPolicy) (*Inbox, error) {
	if isNilStore(store) || policy.Validate() != nil {
		return nil, ErrInvalidInbox
	}
	return &Inbox{store: store, policy: policy}, nil
}
func (i *Inbox) Accept(ctx context.Context, delivery VerifiedDelivery, at time.Time) (AcceptanceReceipt, bool, error) {
	if i == nil || isNilStore(i.store) {
		return AcceptanceReceipt{}, false, ErrInvalidInbox
	}
	if err := validateInboxOperation(ctx); err != nil {
		return AcceptanceReceipt{}, false, err
	}
	if delivery.Validate() != nil {
		return AcceptanceReceipt{}, false, ErrInvalidVerifiedDelivery
	}
	if !i.policy.Allows(delivery) {
		return AcceptanceReceipt{}, false, ErrVerifierNotAuthorized
	}
	stored, created, err := i.store.Put(ctx, delivery, at)
	if err != nil {
		return AcceptanceReceipt{}, false, err
	}
	matchesDelivery := stored.Delivery().Identity() == delivery.Identity()
	if !created {
		matchesDelivery = stored.Delivery().SameContent(delivery)
	}
	if stored.Validate() != nil || !matchesDelivery {
		return AcceptanceReceipt{}, false, ErrInvalidAcceptanceReceipt
	}
	return stored.Receipt(), created, nil
}
func isNilStore(store Store) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	return value.Kind() == reflect.Ptr && value.IsNil()
}
func validateInboxOperation(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidInboxContext
	}
	if ctx.Err() != nil {
		return ErrInboxContextDone
	}
	return nil
}

// MemoryStore is a concurrency-safe bounded-operation in-memory inbox.
type MemoryStore struct {
	mu      sync.RWMutex
	entries map[string]StoredDelivery
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{entries: make(map[string]StoredDelivery)} }
func (s *MemoryStore) Put(ctx context.Context, delivery VerifiedDelivery, at time.Time) (StoredDelivery, bool, error) {
	if err := validateInboxOperation(ctx); err != nil {
		return StoredDelivery{}, false, err
	}
	if s == nil {
		return StoredDelivery{}, false, ErrInvalidInbox
	}
	if delivery.Validate() != nil {
		return StoredDelivery{}, false, ErrInvalidVerifiedDelivery
	}
	stored, err := NewStoredDelivery(delivery, at)
	if err != nil {
		return StoredDelivery{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, found := s.entries[delivery.DeduplicationKey()]; found {
		if !existing.Delivery().SameContent(delivery) {
			return StoredDelivery{}, false, ErrDeliveryConflict
		}
		return existing, false, nil
	}
	if len(s.entries) >= maxMemoryStoreEntries {
		return StoredDelivery{}, false, ErrInboxStoreCapacity
	}
	s.entries[delivery.DeduplicationKey()] = stored
	return stored, true, nil
}
func (s *MemoryStore) Get(ctx context.Context, scope RepositoryScope, source Source, key string) (StoredDelivery, bool, error) {
	if err := validateInboxRead(ctx, scope, source, key, 1); err != nil {
		return StoredDelivery{}, false, err
	}
	if s == nil {
		return StoredDelivery{}, false, ErrInvalidInbox
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	stored, found := s.entries[key]
	if !found || stored.delivery.Scope().Identity() != scope.Identity() || stored.delivery.Source() != source {
		return StoredDelivery{}, false, nil
	}
	return stored, true, nil
}
func (s *MemoryStore) List(ctx context.Context, scope RepositoryScope, source Source, after string, limit int) ([]StoredDelivery, error) {
	if err := validateInboxRead(ctx, scope, source, after, limit); err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrInvalidInbox
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := make([]StoredDelivery, 0)
	for key, stored := range s.entries {
		if key > after && stored.delivery.Scope().Identity() == scope.Identity() && stored.delivery.Source() == source {
			entries = append(entries, stored)
		}
	}
	sort.Slice(entries, func(a, b int) bool {
		return entries[a].delivery.DeduplicationKey() < entries[b].delivery.DeduplicationKey()
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}
func validateInboxRead(ctx context.Context, scope RepositoryScope, source Source, cursor string, limit int) error {
	if err := validateInboxOperation(ctx); err != nil {
		return err
	}
	if scope.Validate() != nil || source.Validate() != nil || cursor != "" && !validWebhookDigest(cursor) || limit <= 0 || limit > maxInboxListLimit {
		return ErrInvalidInboxList
	}
	return nil
}
