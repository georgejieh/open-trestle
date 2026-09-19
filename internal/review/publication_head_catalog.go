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

var (
	// ErrInvalidHeadResolverCatalog identifies an empty or excessive resolver catalog.
	ErrInvalidHeadResolverCatalog = errors.New("invalid publication head resolver catalog")
	// ErrDuplicateHeadResolver identifies competing implementations for one resolver ID.
	ErrDuplicateHeadResolver = errors.New("duplicate publication head resolver")
	// ErrHeadResolverNotRegistered identifies an authorized publisher absent from the catalog.
	ErrHeadResolverNotRegistered = errors.New("publication head resolver not registered")
)

// HeadResolverCatalog is an immutable-to-callers exact-ID resolver map.
type HeadResolverCatalog struct{ resolvers map[string]HeadResolver }

// NewHeadResolverCatalog validates and copies one bounded resolver set.
func NewHeadResolverCatalog(resolvers []HeadResolver) (HeadResolverCatalog, error) {
	if len(resolvers) == 0 || len(resolvers) > maxPublishers {
		return HeadResolverCatalog{}, ErrInvalidHeadResolverCatalog
	}
	catalog := HeadResolverCatalog{resolvers: make(map[string]HeadResolver, len(resolvers))}
	for _, resolver := range resolvers {
		if isNilPublicationInterface(resolver) {
			return HeadResolverCatalog{}, ErrInvalidHeadResolver
		}
		resolverID := resolver.ResolverID()
		if err := ValidatePublisherID(resolverID); err != nil {
			return HeadResolverCatalog{}, err
		}
		if !nonzeroPublicationAuthority(resolver.ConfigurationIdentity()) {
			return HeadResolverCatalog{}, ErrInvalidHeadResolver
		}
		if _, exists := catalog.resolvers[resolverID]; exists {
			return HeadResolverCatalog{}, ErrDuplicateHeadResolver
		}
		catalog.resolvers[resolverID] = resolver
	}
	return catalog, nil
}
func (c HeadResolverCatalog) Identity() string {
	if c.Validate() != nil {
		return ""
	}
	type entry struct {
		ID            string `json:"id"`
		Configuration string `json:"configuration"`
	}
	entries := make([]entry, 0, len(c.resolvers))
	for id, resolver := range c.resolvers {
		entries = append(entries, entry{id, resolver.ConfigurationIdentity()})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	encoded, _ := json.Marshal(struct {
		Contract string  `json:"contract"`
		Version  int     `json:"version"`
		Entries  []entry `json:"entries"`
	}{"open-trestle/head-resolver-catalog", 2, entries})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func (c HeadResolverCatalog) Len() int { return len(c.resolvers) }
func (c HeadResolverCatalog) Resolve(resolverID string) (HeadResolver, bool) {
	if ValidatePublisherID(resolverID) != nil {
		return nil, false
	}
	resolver, exists := c.resolvers[resolverID]
	return resolver, exists && !isNilPublicationInterface(resolver)
}
func (c HeadResolverCatalog) Validate() error {
	if len(c.resolvers) == 0 || len(c.resolvers) > maxPublishers {
		return ErrInvalidHeadResolverCatalog
	}
	for resolverID, resolver := range c.resolvers {
		if ValidatePublisherID(resolverID) != nil || isNilPublicationInterface(resolver) || resolver.ResolverID() != resolverID || !nonzeroPublicationAuthority(resolver.ConfigurationIdentity()) {
			return ErrPublicationHeadResolverMismatch
		}
	}
	return nil
}
func (c HeadResolverCatalog) String() string   { return "publication head resolver catalog" }
func (c HeadResolverCatalog) GoString() string { return "review.HeadResolverCatalog{<redacted>}" }
func (c HeadResolverCatalog) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication head resolver catalog", "review.HeadResolverCatalog{<redacted>}")
}

// ResolvePublicationHeadFromCatalog invokes only the exact target resolver.
func ResolvePublicationHeadFromCatalog(
	ctx context.Context,
	catalog HeadResolverCatalog,
	scope audit.ReviewScope,
	authorization PublicationAuthorization,
	claim PublicationClaim,
	attempt PublicationAttemptAuthorization,
	observedAt time.Time,
) (PublicationHeadObservation, error) {
	if err := catalog.Validate(); err != nil {
		return PublicationHeadObservation{}, err
	}
	if err := authorization.Validate(); err != nil {
		return PublicationHeadObservation{}, err
	}
	resolver, exists := catalog.Resolve(authorization.Plan().Target().PublisherID())
	if !exists {
		return PublicationHeadObservation{}, ErrHeadResolverNotRegistered
	}
	return ResolvePublicationHead(ctx, resolver, scope, authorization, claim, attempt, observedAt)
}
