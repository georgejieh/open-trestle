package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

const (
	maxExternalPublicationReferenceBytes        = 4 << 10
	maxPublicationRetryAfterMilliseconds uint32 = 86_400_000
)

var (
	// ErrInvalidPublisherContext identifies a nil dispatch context.
	ErrInvalidPublisherContext = errors.New("invalid publication context")
	// ErrPublisherContextDone identifies cancellation before publisher dispatch.
	ErrPublisherContextDone = errors.New("publication context done")
	// ErrInvalidPublisher identifies a missing publisher implementation.
	ErrInvalidPublisher = errors.New("invalid publisher")
	// ErrPublicationPublisherMismatch identifies an implementation other than the exact target publisher.
	ErrPublicationPublisherMismatch = errors.New("publication publisher mismatch")
	// ErrPublicationIdempotencyNotGuaranteed identifies a publisher unsafe for effect retries.
	ErrPublicationIdempotencyNotGuaranteed = errors.New("publication idempotency not guaranteed")
	// ErrInvalidPublicationStatus identifies an unknown publisher result state.
	ErrInvalidPublicationStatus = errors.New("invalid publication status")
	// ErrInvalidPublicationFailure identifies an unknown publisher failure class.
	ErrInvalidPublicationFailure = errors.New("invalid publication failure")
	// ErrInvalidPublicationRetryAfter identifies retry metadata on a non-rate-limit failure or beyond its bound.
	ErrInvalidPublicationRetryAfter = errors.New("invalid publication retry after")
	// ErrInvalidExternalPublicationReference identifies an empty or excessive provider result reference.
	ErrInvalidExternalPublicationReference = errors.New("invalid external publication reference")
	// ErrInvalidPublicationResult identifies inconsistent success, failure, authorization, or claim fields.
	ErrInvalidPublicationResult = errors.New("invalid publication result")
	// ErrInvalidPublicationResultIdentity identifies result content inconsistent with its identity.
	ErrInvalidPublicationResultIdentity = errors.New("invalid publication result identity")
)

// PublicationDispatchRequest is the exact claimed and authorized request visible to a publisher.
type PublicationDispatchRequest struct {
	scope         audit.ReviewScope
	authorization PublicationAuthorization
	claim         PublicationClaim
	attempt       PublicationAttemptAuthorization
	headGate      PublicationHeadGate
}

func (r PublicationDispatchRequest) Scope() audit.ReviewScope                 { return r.scope }
func (r PublicationDispatchRequest) Authorization() PublicationAuthorization  { return r.authorization }
func (r PublicationDispatchRequest) Claim() PublicationClaim                  { return r.claim }
func (r PublicationDispatchRequest) Attempt() PublicationAttemptAuthorization { return r.attempt }
func (r PublicationDispatchRequest) HeadGate() PublicationHeadGate            { return r.headGate }
func (r PublicationDispatchRequest) IdempotencyKey() string                   { return r.authorization.IdempotencyKey() }
func (r PublicationDispatchRequest) String() string                           { return "publication dispatch request" }
func (r PublicationDispatchRequest) GoString() string {
	return "review.PublicationDispatchRequest{<redacted>}"
}
func (r PublicationDispatchRequest) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication dispatch request", "review.PublicationDispatchRequest{<redacted>}")
}

// Validate verifies exact authorization, claim, plan, target, and idempotency lineage.
func (r PublicationDispatchRequest) Validate() error {
	if err := r.scope.Validate(); err != nil {
		return err
	}
	if err := r.authorization.Validate(); err != nil {
		return err
	}
	if err := r.claim.Validate(); err != nil {
		return err
	}
	if err := r.attempt.Validate(); err != nil {
		return err
	}
	if err := r.headGate.Validate(); err != nil {
		return err
	}
	matchingAuthorization := r.claim.AuthorizationIdentity() == r.authorization.Identity()
	matchingPlan := r.claim.PlanIdentity() == r.authorization.PlanIdentity()
	matchingTarget := r.claim.TargetIdentity() == r.authorization.TargetIdentity()
	matchingKey := r.claim.IdempotencyKey() == r.authorization.IdempotencyKey()
	matchingAttempt := r.attempt.AuthorizationIdentity() == r.authorization.Identity() && r.attempt.ClaimIdentity() == r.claim.Identity()
	reconciliation := r.headGate.Reconciliation()
	matchingHeadAuthorization := reconciliation.AuthorizationIdentity() == r.authorization.Identity()
	matchingHeadClaim := reconciliation.ClaimIdentity() == r.claim.Identity()
	matchingHeadAttempt := reconciliation.AttemptIdentity() == r.attempt.Identity()
	matchingHeadTarget := reconciliation.TargetIdentity() == r.authorization.TargetIdentity()
	matchingHeadGate := matchingHeadAuthorization && matchingHeadClaim && matchingHeadAttempt && matchingHeadTarget
	matchingScope := r.authorization.Plan().ReviewScopeIdentity() == r.scope.Identity() && r.claim.ReviewScopeIdentity() == r.scope.Identity()
	if !matchingScope || !matchingAuthorization || !matchingPlan || !matchingTarget || !matchingKey || !matchingAttempt || !matchingHeadGate {
		return ErrInvalidPublicationClaim
	}
	return nil
}

// ValidateAt verifies exact lineage and the time-bound authority for one dispatch.
func (r PublicationDispatchRequest) ValidateAt(at time.Time) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if !r.authorization.Authorizes(r.authorization.Plan().Target(), at) {
		return ErrPublicationNotAuthorized
	}
	if !r.attempt.Ready(at) {
		return ErrPublicationRetryNotAllowed
	}
	if !r.headGate.AuthorizesPublication() {
		return ErrPublicationHeadNotCurrent
	}
	headAge := at.UnixMilli() - r.headGate.Reconciliation().EvaluatedAt().UnixMilli()
	if headAge < 0 || headAge > maxPublicationHeadAgeMilliseconds {
		return ErrPublicationHeadNotCurrent
	}
	return nil
}

// RemainingDispatchTime bounds transport work by the live grant and head freshness.
func (r PublicationDispatchRequest) RemainingDispatchTime(at time.Time) (time.Duration, error) {
	if err := r.ValidateAt(at); err != nil {
		return 0, err
	}
	headDeadline := r.headGate.Reconciliation().EvaluatedAt().Add(time.Duration(maxPublicationHeadAgeMilliseconds) * time.Millisecond)
	remaining := headDeadline.Sub(at)
	if remaining <= 0 {
		return 0, ErrPublicationHeadNotCurrent
	}
	grantDeadline := time.UnixMilli(r.authorization.EffectAuthorization().ExpiresAtUnixMilliseconds())
	if grantRemaining := grantDeadline.Sub(at); grantRemaining < remaining {
		remaining = grantRemaining
	}
	return remaining, nil
}

// PublisherIdempotencyGuarantee declares how an adapter handles repeated operation keys.
type PublisherIdempotencyGuarantee uint8

const (
	// PublisherExactOperationKey requires equivalent requests to produce at most one external effect.
	PublisherExactOperationKey PublisherIdempotencyGuarantee = iota + 1
)

func (g PublisherIdempotencyGuarantee) Validate() error {
	if g != PublisherExactOperationKey {
		return ErrPublicationIdempotencyNotGuaranteed
	}
	return nil
}

// Publisher performs one idempotent external publication for an exact target.
type Publisher interface {
	PublisherID() string
	ConfigurationIdentity() string
	IdempotencyGuarantee() PublisherIdempotencyGuarantee
	Publish(context.Context, PublicationDispatchRequest) PublicationResult
}

// DispatchClaimedPublication releases plan content only to the exact publisher after all gates.
func DispatchClaimedPublication(
	ctx context.Context,
	publisher Publisher,
	scope audit.ReviewScope,
	authorization PublicationAuthorization,
	claim PublicationClaim,
	attempt PublicationAttemptAuthorization,
	headGate PublicationHeadGate,
	at time.Time,
) (PublicationResult, error) {
	if isNilPublicationInterface(ctx) {
		return PublicationResult{}, ErrInvalidPublisherContext
	}
	if err := ctx.Err(); err != nil {
		return PublicationResult{}, fmt.Errorf("%w: %v", ErrPublisherContextDone, err)
	}
	if isNilPublicationInterface(publisher) {
		return PublicationResult{}, ErrInvalidPublisher
	}
	request := PublicationDispatchRequest{scope: scope, authorization: authorization, claim: claim, attempt: attempt, headGate: headGate}
	if err := request.ValidateAt(at); err != nil {
		return PublicationResult{}, err
	}
	target := authorization.Plan().Target()
	if publisher.PublisherID() != target.PublisherID() || !nonzeroPublicationAuthority(publisher.ConfigurationIdentity()) {
		return PublicationResult{}, ErrPublicationPublisherMismatch
	}
	if publisher.IdempotencyGuarantee().Validate() != nil {
		return PublicationResult{}, ErrPublicationIdempotencyNotGuaranteed
	}
	result := publisher.Publish(ctx, request)
	if err := result.Validate(); err != nil || result.AuthorizationIdentity() != "" || result.ClaimIdentity() != "" || result.AttemptIdentity() != "" || result.HeadReconciliationIdentity() != "" {
		return PublicationResult{}, ErrInvalidPublicationResult
	}
	result.authorizationIdentity = authorization.Identity()
	result.claimIdentity = claim.Identity()
	result.attemptIdentity = attempt.Identity()
	result.headReconciliationIdentity = headGate.Reconciliation().Identity()
	result.identity = derivePublicationResultIdentity(result)
	if err := result.Validate(); err != nil {
		return PublicationResult{}, err
	}
	return result, nil
}

func isNilPublicationInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// PublicationStatus identifies whether the publisher completed or failed.
type PublicationStatus uint8

const (
	PublicationSucceeded PublicationStatus = iota + 1
	PublicationFailed
)

func (s PublicationStatus) String() string {
	if s == PublicationSucceeded {
		return "succeeded"
	}
	if s == PublicationFailed {
		return "failed"
	}
	return ""
}

func (s PublicationStatus) Validate() error {
	if s.String() == "" {
		return ErrInvalidPublicationStatus
	}
	return nil
}

// PublicationFailure is a closed publisher-neutral failure classification.
type PublicationFailure uint8

const (
	PublicationFailureTransient PublicationFailure = iota + 1
	PublicationFailureRateLimited
	PublicationFailureStaleHead
	PublicationFailureAuthorization
	PublicationFailureValidation
	PublicationFailureProvider
	PublicationFailureCancelled
)

func (f PublicationFailure) String() string {
	switch f {
	case PublicationFailureTransient:
		return "transient"
	case PublicationFailureRateLimited:
		return "rate_limited"
	case PublicationFailureStaleHead:
		return "stale_head"
	case PublicationFailureAuthorization:
		return "authorization"
	case PublicationFailureValidation:
		return "validation"
	case PublicationFailureProvider:
		return "provider"
	case PublicationFailureCancelled:
		return "cancelled"
	default:
		return ""
	}
}

func (f PublicationFailure) Validate() error {
	if f.String() == "" {
		return ErrInvalidPublicationFailure
	}
	return nil
}

// PublicationResult is closed, content-addressed publisher output.
type PublicationResult struct {
	identity                   string
	authorizationIdentity      string
	claimIdentity              string
	attemptIdentity            string
	headReconciliationIdentity string
	status                     PublicationStatus
	externalReferenceIdentity  string
	failure                    PublicationFailure
	retryAfterMilliseconds     uint32
}

// NewSuccessfulPublicationResult hashes and discards the external provider reference.
func NewSuccessfulPublicationResult(externalReference string) (PublicationResult, error) {
	if len(externalReference) == 0 || len(externalReference) > maxExternalPublicationReferenceBytes {
		return PublicationResult{}, ErrInvalidExternalPublicationReference
	}
	digest := sha256.Sum256([]byte(externalReference))
	result := PublicationResult{status: PublicationSucceeded, externalReferenceIdentity: hex.EncodeToString(digest[:])}
	result.identity = derivePublicationResultIdentity(result)
	return result, nil
}

// NewFailedPublicationResult creates one closed failure result.
func NewFailedPublicationResult(failure PublicationFailure, retryAfterMilliseconds uint32) (PublicationResult, error) {
	result := PublicationResult{status: PublicationFailed, failure: failure, retryAfterMilliseconds: retryAfterMilliseconds}
	if err := result.validateFields(); err != nil {
		return PublicationResult{}, err
	}
	result.identity = derivePublicationResultIdentity(result)
	return result, nil
}

func (r PublicationResult) Identity() string                   { return r.identity }
func (r PublicationResult) AuthorizationIdentity() string      { return r.authorizationIdentity }
func (r PublicationResult) ClaimIdentity() string              { return r.claimIdentity }
func (r PublicationResult) AttemptIdentity() string            { return r.attemptIdentity }
func (r PublicationResult) HeadReconciliationIdentity() string { return r.headReconciliationIdentity }
func (r PublicationResult) Status() PublicationStatus          { return r.status }
func (r PublicationResult) ExternalReferenceIdentity() string  { return r.externalReferenceIdentity }
func (r PublicationResult) Failure() PublicationFailure        { return r.failure }
func (r PublicationResult) RetryAfterMilliseconds() uint32     { return r.retryAfterMilliseconds }
func (r PublicationResult) String() string                     { return "publication result" }
func (r PublicationResult) GoString() string                   { return "review.PublicationResult{<redacted>}" }
func (r PublicationResult) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication result", "review.PublicationResult{<redacted>}")
}

// Validate verifies closed result semantics, optional bindings, and content identity.
func (r PublicationResult) Validate() error {
	if err := r.validateFields(); err != nil {
		return err
	}
	if r.identity != derivePublicationResultIdentity(r) {
		return ErrInvalidPublicationResultIdentity
	}
	return nil
}

func (r PublicationResult) validateFields() error {
	validAuthorization := r.authorizationIdentity == "" || validCandidateDigest(r.authorizationIdentity)
	validClaim := r.claimIdentity == "" || validCandidateDigest(r.claimIdentity)
	validAttempt := r.attemptIdentity == "" || validCandidateDigest(r.attemptIdentity)
	validReconciliation := r.headReconciliationIdentity == "" || validCandidateDigest(r.headReconciliationIdentity)
	if !validAuthorization || !validClaim || !validAttempt || !validReconciliation {
		return ErrInvalidPublicationResult
	}
	boundFields := 0
	for _, identity := range []string{r.authorizationIdentity, r.claimIdentity, r.attemptIdentity, r.headReconciliationIdentity} {
		if identity != "" {
			boundFields++
		}
	}
	if boundFields != 0 && boundFields != 4 {
		return ErrInvalidPublicationResult
	}
	if err := r.status.Validate(); err != nil {
		return err
	}
	if r.status == PublicationSucceeded {
		if !validCandidateDigest(r.externalReferenceIdentity) || r.failure != 0 || r.retryAfterMilliseconds != 0 {
			return ErrInvalidPublicationResult
		}
		return nil
	}
	if r.externalReferenceIdentity != "" {
		return ErrInvalidPublicationResult
	}
	if err := r.failure.Validate(); err != nil {
		return err
	}
	if r.retryAfterMilliseconds > maxPublicationRetryAfterMilliseconds || r.retryAfterMilliseconds != 0 && r.failure != PublicationFailureRateLimited {
		return ErrInvalidPublicationRetryAfter
	}
	return nil
}

func derivePublicationResultIdentity(result PublicationResult) string {
	preimage := struct {
		Contract           string `json:"contract"`
		Version            int    `json:"version"`
		Authorization      string `json:"authorization"`
		Claim              string `json:"claim"`
		Attempt            string `json:"attempt"`
		HeadReconciliation string `json:"head_reconciliation"`
		Status             string `json:"status"`
		ExternalReference  string `json:"external_reference"`
		Failure            string `json:"failure"`
		RetryAfter         uint32 `json:"retry_after"`
	}{
		Contract: "open-trestle/publication-result", Version: 1,
		Authorization: result.authorizationIdentity, Claim: result.claimIdentity, Attempt: result.attemptIdentity,
		HeadReconciliation: result.headReconciliationIdentity, Status: result.status.String(), ExternalReference: result.externalReferenceIdentity,
		Failure: result.failure.String(), RetryAfter: result.retryAfterMilliseconds,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
