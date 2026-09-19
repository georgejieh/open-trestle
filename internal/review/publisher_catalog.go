package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

const maxPublishers = 16

var (
	// ErrInvalidPublisherCatalog identifies an empty or excessive implementation catalog.
	ErrInvalidPublisherCatalog = errors.New("invalid publisher catalog")
	// ErrDuplicatePublisher identifies competing implementations for one publisher ID.
	ErrDuplicatePublisher = errors.New("duplicate publisher")
	// ErrPublisherNotRegistered identifies an authorized target absent from the catalog.
	ErrPublisherNotRegistered = errors.New("publisher not registered")
)

// PublisherCatalog is an immutable-to-callers exact-ID implementation map.
type PublisherCatalog struct {
	publishers map[string]Publisher
}

// NewPublisherCatalog validates and copies one bounded publisher set.
func NewPublisherCatalog(publishers []Publisher) (PublisherCatalog, error) {
	if len(publishers) == 0 || len(publishers) > maxPublishers {
		return PublisherCatalog{}, ErrInvalidPublisherCatalog
	}
	catalog := PublisherCatalog{publishers: make(map[string]Publisher, len(publishers))}
	for _, publisher := range publishers {
		if isNilPublicationInterface(publisher) {
			return PublisherCatalog{}, ErrInvalidPublisher
		}
		publisherID := publisher.PublisherID()
		if err := ValidatePublisherID(publisherID); err != nil {
			return PublisherCatalog{}, err
		}
		if !nonzeroPublicationAuthority(publisher.ConfigurationIdentity()) {
			return PublisherCatalog{}, ErrInvalidPublisher
		}
		if publisher.IdempotencyGuarantee().Validate() != nil {
			return PublisherCatalog{}, ErrPublicationIdempotencyNotGuaranteed
		}
		if _, exists := catalog.publishers[publisherID]; exists {
			return PublisherCatalog{}, ErrDuplicatePublisher
		}
		catalog.publishers[publisherID] = publisher
	}
	return catalog, nil
}

func (c PublisherCatalog) Identity() string {
	if c.Validate() != nil {
		return ""
	}
	type entry struct {
		ID            string `json:"id"`
		Configuration string `json:"configuration"`
	}
	entries := make([]entry, 0, len(c.publishers))
	for id, publisher := range c.publishers {
		entries = append(entries, entry{id, publisher.ConfigurationIdentity()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	encoded, _ := json.Marshal(struct {
		Contract string  `json:"contract"`
		Version  int     `json:"version"`
		Entries  []entry `json:"entries"`
	}{"open-trestle/publisher-catalog", 2, entries})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func (c PublisherCatalog) Len() int { return len(c.publishers) }

// Resolve returns the implementation registered for one exact publisher ID.
func (c PublisherCatalog) Resolve(publisherID string) (Publisher, bool) {
	if ValidatePublisherID(publisherID) != nil {
		return nil, false
	}
	publisher, exists := c.publishers[publisherID]
	return publisher, exists && !isNilPublicationInterface(publisher)
}

// Validate verifies bounds, exact keys, and implementation self-identities.
func (c PublisherCatalog) Validate() error {
	if len(c.publishers) == 0 || len(c.publishers) > maxPublishers {
		return ErrInvalidPublisherCatalog
	}
	for publisherID, publisher := range c.publishers {
		if ValidatePublisherID(publisherID) != nil || isNilPublicationInterface(publisher) || publisher.PublisherID() != publisherID || !nonzeroPublicationAuthority(publisher.ConfigurationIdentity()) || publisher.IdempotencyGuarantee().Validate() != nil {
			return ErrPublicationPublisherMismatch
		}
	}
	return nil
}

func (c PublisherCatalog) String() string   { return "publisher catalog" }
func (c PublisherCatalog) GoString() string { return "review.PublisherCatalog{<redacted>}" }
func (c PublisherCatalog) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publisher catalog", "review.PublisherCatalog{<redacted>}")
}

// DispatchClaimedPublicationFromCatalog resolves only the exact authorized publisher.
func DispatchClaimedPublicationFromCatalog(
	ctx context.Context,
	catalog PublisherCatalog,
	scope audit.ReviewScope,
	authorization PublicationAuthorization,
	claim PublicationClaim,
	attempt PublicationAttemptAuthorization,
	headGate PublicationHeadGate,
	at time.Time,
) (PublicationResult, error) {
	if err := catalog.Validate(); err != nil {
		return PublicationResult{}, err
	}
	if err := authorization.Validate(); err != nil {
		return PublicationResult{}, err
	}
	publisher, exists := catalog.Resolve(authorization.Plan().Target().PublisherID())
	if !exists {
		return PublicationResult{}, ErrPublisherNotRegistered
	}
	return DispatchClaimedPublication(ctx, publisher, scope, authorization, claim, attempt, headGate, at)
}
