// Package fake provides a deterministic idempotent source-control publisher.
package fake

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

var (
	// ErrInvalidPublisherResult identifies a bound or malformed configured result.
	ErrInvalidPublisherResult = errors.New("invalid fake publisher result")
)

// Publisher applies one configured result per unique publication idempotency key.
type Publisher struct {
	mu                    sync.Mutex
	publisherID           string
	configurationIdentity string
	result                review.PublicationResult
	currentHead           evidence.RevisionIdentity
	published             map[string]review.PublicationResult
}

// NewPublisher creates a deterministic publisher with an unbound result.
func NewPublisher(publisherID string, result review.PublicationResult) (*Publisher, error) {
	if err := review.ValidatePublisherID(publisherID); err != nil {
		return nil, err
	}
	if err := result.Validate(); err != nil || result.AuthorizationIdentity() != "" || result.ClaimIdentity() != "" || result.AttemptIdentity() != "" || result.HeadReconciliationIdentity() != "" {
		return nil, ErrInvalidPublisherResult
	}
	publisher := &Publisher{publisherID: publisherID, result: result, published: make(map[string]review.PublicationResult)}
	publisher.configurationIdentity = deriveFakePublisherConfigurationIdentity(publisher)
	return publisher, nil
}

// NewAdapter creates a fake publisher and current-head resolver.
func NewAdapter(publisherID string, currentHead evidence.RevisionIdentity, result review.PublicationResult) (*Publisher, error) {
	publisher, err := NewPublisher(publisherID, result)
	if err != nil {
		return nil, err
	}
	canonicalHead, err := evidence.NewRevisionIdentity(currentHead.Kind(), currentHead.Algorithm(), currentHead.Digest())
	if err != nil || canonicalHead != currentHead {
		return nil, review.ErrInvalidPublicationHeadObservation
	}
	publisher.currentHead = canonicalHead
	return publisher, nil
}

// ResolverID returns the exact implementation ID shared with publication.
func (p *Publisher) ResolverID() string { return p.PublisherID() }

// ResolveHead returns the configured moving head without external effects.
func (p *Publisher) ResolveHead(ctx context.Context, request review.PublicationHeadRequest) review.PublicationHeadObservation {
	if isNilContext(ctx) {
		return closedHeadFailure(review.PublicationHeadFailureProvider)
	}
	if ctx.Err() != nil {
		return closedHeadFailure(review.PublicationHeadFailureTransient)
	}
	if p == nil || request.Validate() != nil {
		return closedHeadFailure(review.PublicationHeadFailureProvider)
	}
	if request.Target().PublisherID() != p.publisherID {
		return closedHeadFailure(review.PublicationHeadFailureAuthorization)
	}
	p.mu.Lock()
	head := p.currentHead
	p.mu.Unlock()
	if head.Identity() == "" {
		return closedHeadFailure(review.PublicationHeadFailureNotFound)
	}
	observation, _ := review.NewResolvedPublicationHeadObservation(head)
	return observation
}

// SetCurrentHead changes the deterministic fake resolver state.
func (p *Publisher) SetCurrentHead(head evidence.RevisionIdentity) error {
	canonical, err := evidence.NewRevisionIdentity(head.Kind(), head.Algorithm(), head.Digest())
	if err != nil || canonical != head {
		return review.ErrInvalidPublicationHeadObservation
	}
	if p == nil {
		return ErrInvalidPublisherResult
	}
	p.mu.Lock()
	p.currentHead = canonical
	p.mu.Unlock()
	return nil
}

func (p *Publisher) IdempotencyGuarantee() review.PublisherIdempotencyGuarantee {
	return review.PublisherExactOperationKey
}

func (p *Publisher) ConfigurationIdentity() string {
	if p == nil {
		return ""
	}
	return p.configurationIdentity
}
func deriveFakePublisherConfigurationIdentity(p *Publisher) string {
	if p == nil {
		return ""
	}
	encoded, _ := json.Marshal(struct {
		Contract  string `json:"contract"`
		Version   int    `json:"version"`
		Publisher string `json:"publisher"`
		Result    string `json:"result"`
	}{"open-trestle/fake-publisher", 1, p.publisherID, p.result.Identity()})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func (p *Publisher) PublisherID() string {
	if p == nil {
		return ""
	}
	return p.publisherID
}

// Publish validates the exact dispatch request and deduplicates by its host-issued key.
func (p *Publisher) Publish(ctx context.Context, request review.PublicationDispatchRequest) review.PublicationResult {
	if isNilContext(ctx) {
		return closedFailure(review.PublicationFailureValidation)
	}
	if ctx.Err() != nil {
		return closedFailure(review.PublicationFailureCancelled)
	}
	if p == nil || request.Validate() != nil {
		return closedFailure(review.PublicationFailureValidation)
	}
	if request.Authorization().Plan().Target().PublisherID() != p.publisherID {
		return closedFailure(review.PublicationFailureAuthorization)
	}
	return p.recordPublication(request.IdempotencyKey())
}

func (p *Publisher) recordPublication(idempotencyKey string) review.PublicationResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	if result, exists := p.published[idempotencyKey]; exists {
		return result
	}
	p.published[idempotencyKey] = p.result
	return p.result
}

func (p *Publisher) PublishedCount() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.published)
}

// Validate verifies the implementation ID, configured result, and stored idempotent results.
func (p *Publisher) Validate() error {
	if p == nil {
		return ErrInvalidPublisherResult
	}
	if err := review.ValidatePublisherID(p.publisherID); err != nil {
		return err
	}
	if p.configurationIdentity != deriveFakePublisherConfigurationIdentity(p) {
		return ErrInvalidPublisherResult
	}
	if err := p.result.Validate(); err != nil || p.result.AuthorizationIdentity() != "" || p.result.ClaimIdentity() != "" {
		return ErrInvalidPublisherResult
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.currentHead.Identity() != "" {
		canonicalHead, err := evidence.NewRevisionIdentity(p.currentHead.Kind(), p.currentHead.Algorithm(), p.currentHead.Digest())
		if err != nil || canonicalHead != p.currentHead {
			return ErrInvalidPublisherResult
		}
	}
	for key, result := range p.published {
		if len(key) != 64 || result.Identity() != p.result.Identity() {
			return ErrInvalidPublisherResult
		}
	}
	return nil
}

func (p *Publisher) String() string   { return "fake source-control publisher" }
func (p *Publisher) GoString() string { return "fake.Publisher{<redacted>}" }
func (p *Publisher) Format(state fmt.State, verb rune) {
	formatted := "fake source-control publisher"
	if verb == 'q' {
		formatted = `"fake source-control publisher"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "fake.Publisher{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

func closedHeadFailure(failure review.PublicationHeadFailure) review.PublicationHeadObservation {
	observation, _ := review.NewFailedPublicationHeadObservation(failure)
	return observation
}

func closedFailure(failure review.PublicationFailure) review.PublicationResult {
	result, _ := review.NewFailedPublicationResult(failure, 0)
	return result
}

func isNilContext(ctx context.Context) bool {
	if ctx == nil {
		return true
	}
	value := reflect.ValueOf(ctx)
	return value.Kind() == reflect.Pointer && value.IsNil()
}
