package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	maxPublicationHeadAgeMilliseconds  = int64(2_000)
	maxPublicationHeadUnixMilliseconds = int64(253_402_300_799_999)
)

var (
	// ErrInvalidHeadResolver identifies a missing head resolver implementation.
	ErrInvalidHeadResolver = errors.New("invalid publication head resolver")
	// ErrPublicationHeadResolverMismatch identifies a resolver other than the target publisher.
	ErrPublicationHeadResolverMismatch = errors.New("publication head resolver mismatch")
	// ErrInvalidPublicationHeadRequest identifies inconsistent authorization, claim, or target lineage.
	ErrInvalidPublicationHeadRequest = errors.New("invalid publication head request")
	// ErrInvalidPublicationHeadObservation identifies inconsistent closed resolver output.
	ErrInvalidPublicationHeadObservation = errors.New("invalid publication head observation")
	// ErrInvalidPublicationHeadObservationIdentity identifies observation content inconsistent with its identity.
	ErrInvalidPublicationHeadObservationIdentity = errors.New("invalid publication head observation identity")
	// ErrInvalidPublicationHeadReconciliation identifies inconsistent or stale comparison evidence.
	ErrInvalidPublicationHeadReconciliation = errors.New("invalid publication head reconciliation")
	// ErrInvalidPublicationHeadReconciliationIdentity identifies reconciliation content inconsistent with its identity.
	ErrInvalidPublicationHeadReconciliationIdentity = errors.New("invalid publication head reconciliation identity")
	// ErrPublicationHeadNotCurrent identifies a stale or unavailable head at dispatch time.
	ErrPublicationHeadNotCurrent = errors.New("publication head is not current")
	// ErrPublicationHeadReconciliationConflict identifies a second head decision for one claim.
	ErrPublicationHeadReconciliationConflict = errors.New("publication head reconciliation conflict")
	// ErrInvalidPublicationHeadGate identifies an inconsistent audited reconciliation.
	ErrInvalidPublicationHeadGate = errors.New("invalid publication head gate")
	// ErrInvalidPublicationHeadGateIdentity identifies gate content inconsistent with its identity.
	ErrInvalidPublicationHeadGateIdentity = errors.New("invalid publication head gate identity")
)

// PublicationHeadRequest asks the target publisher for the current head of one change.
type PublicationHeadRequest struct {
	scope                 audit.ReviewScope
	identity              string
	target                PublicationTarget
	authorizationIdentity string
	reviewScopeIdentity   string
	claimIdentity         string
	attemptIdentity       string
}

func newPublicationHeadRequest(scope audit.ReviewScope, authorization PublicationAuthorization, claim PublicationClaim, attempt PublicationAttemptAuthorization) (PublicationHeadRequest, error) {
	if err := scope.Validate(); err != nil {
		return PublicationHeadRequest{}, err
	}
	if err := authorization.Validate(); err != nil {
		return PublicationHeadRequest{}, err
	}
	if err := claim.Validate(); err != nil {
		return PublicationHeadRequest{}, err
	}
	matchingAuthorization := claim.AuthorizationIdentity() == authorization.Identity()
	matchingPlan := claim.PlanIdentity() == authorization.PlanIdentity()
	matchingTarget := claim.TargetIdentity() == authorization.TargetIdentity()
	matchingKey := claim.IdempotencyKey() == authorization.IdempotencyKey()
	if !matchingAuthorization || !matchingPlan || !matchingTarget || !matchingKey {
		return PublicationHeadRequest{}, ErrInvalidPublicationHeadRequest
	}
	if err := attempt.Validate(); err != nil {
		return PublicationHeadRequest{}, err
	}
	if attempt.AuthorizationIdentity() != authorization.Identity() || attempt.ClaimIdentity() != claim.Identity() {
		return PublicationHeadRequest{}, ErrInvalidPublicationHeadRequest
	}
	request := PublicationHeadRequest{
		scope: scope, target: authorization.Plan().Target(), reviewScopeIdentity: authorization.Plan().ReviewScopeIdentity(), authorizationIdentity: authorization.Identity(), claimIdentity: claim.Identity(), attemptIdentity: attempt.Identity(),
	}
	request.identity = derivePublicationHeadRequestIdentity(request)
	if err := request.Validate(); err != nil {
		return PublicationHeadRequest{}, err
	}
	return request, nil
}

func (r PublicationHeadRequest) Scope() audit.ReviewScope      { return r.scope }
func (r PublicationHeadRequest) Identity() string              { return r.identity }
func (r PublicationHeadRequest) Target() PublicationTarget     { return r.target }
func (r PublicationHeadRequest) AuthorizationIdentity() string { return r.authorizationIdentity }
func (r PublicationHeadRequest) ClaimIdentity() string         { return r.claimIdentity }
func (r PublicationHeadRequest) String() string                { return "publication head request" }
func (r PublicationHeadRequest) GoString() string              { return "review.PublicationHeadRequest{<redacted>}" }
func (r PublicationHeadRequest) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication head request", "review.PublicationHeadRequest{<redacted>}")
}

func (r PublicationHeadRequest) Validate() error {
	if err := r.scope.Validate(); err != nil || r.scope.Identity() != r.reviewScopeIdentity {
		return ErrInvalidPublicationHeadRequest
	}
	if err := r.target.Validate(); err != nil || !validCandidateDigest(r.authorizationIdentity) || !validCandidateDigest(r.claimIdentity) || !validCandidateDigest(r.attemptIdentity) {
		return ErrInvalidPublicationHeadRequest
	}
	if r.identity != derivePublicationHeadRequestIdentity(r) {
		return ErrInvalidPublicationHeadRequest
	}
	return nil
}

// HeadResolver resolves a moving change head without publishing content.
type HeadResolver interface {
	ResolverID() string
	ConfigurationIdentity() string
	ResolveHead(context.Context, PublicationHeadRequest) PublicationHeadObservation
}

// PublicationHeadObservationStatus identifies closed resolver output.
type PublicationHeadObservationStatus uint8

const (
	PublicationHeadResolved PublicationHeadObservationStatus = iota + 1
	PublicationHeadResolutionFailed
)

func (s PublicationHeadObservationStatus) String() string {
	switch s {
	case PublicationHeadResolved:
		return "resolved"
	case PublicationHeadResolutionFailed:
		return "failed"
	default:
		return ""
	}
}

// PublicationHeadFailure is a closed resolver failure classification.
type PublicationHeadFailure uint8

const (
	PublicationHeadFailureNotFound PublicationHeadFailure = iota + 1
	PublicationHeadFailureAuthorization
	PublicationHeadFailureTransient
	PublicationHeadFailureProvider
)

func (f PublicationHeadFailure) String() string {
	switch f {
	case PublicationHeadFailureNotFound:
		return "not_found"
	case PublicationHeadFailureAuthorization:
		return "authorization"
	case PublicationHeadFailureTransient:
		return "transient"
	case PublicationHeadFailureProvider:
		return "provider"
	default:
		return ""
	}
}

// PublicationHeadObservation is a bounded, content-addressed resolver result.
type PublicationHeadObservation struct {
	identity         string
	requestIdentity  string
	resolverID       string
	status           PublicationHeadObservationStatus
	currentHead      evidence.RevisionIdentity
	failure          PublicationHeadFailure
	observedAtMillis int64
}

func NewResolvedPublicationHeadObservation(currentHead evidence.RevisionIdentity) (PublicationHeadObservation, error) {
	canonical, err := canonicalPublicationRevision(currentHead)
	if err != nil {
		return PublicationHeadObservation{}, ErrInvalidPublicationHeadObservation
	}
	observation := PublicationHeadObservation{status: PublicationHeadResolved, currentHead: canonical}
	observation.identity = derivePublicationHeadObservationIdentity(observation)
	return observation, nil
}

func NewFailedPublicationHeadObservation(failure PublicationHeadFailure) (PublicationHeadObservation, error) {
	if failure.String() == "" {
		return PublicationHeadObservation{}, ErrInvalidPublicationHeadObservation
	}
	observation := PublicationHeadObservation{status: PublicationHeadResolutionFailed, failure: failure}
	observation.identity = derivePublicationHeadObservationIdentity(observation)
	return observation, nil
}

func (o PublicationHeadObservation) Identity() string                         { return o.identity }
func (o PublicationHeadObservation) RequestIdentity() string                  { return o.requestIdentity }
func (o PublicationHeadObservation) ResolverID() string                       { return o.resolverID }
func (o PublicationHeadObservation) Status() PublicationHeadObservationStatus { return o.status }
func (o PublicationHeadObservation) CurrentHead() evidence.RevisionIdentity   { return o.currentHead }
func (o PublicationHeadObservation) Failure() PublicationHeadFailure          { return o.failure }
func (o PublicationHeadObservation) ObservedAt() time.Time {
	return time.UnixMilli(o.observedAtMillis).UTC()
}
func (o PublicationHeadObservation) String() string { return "publication head observation" }
func (o PublicationHeadObservation) GoString() string {
	return "review.PublicationHeadObservation{<redacted>}"
}
func (o PublicationHeadObservation) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication head observation", "review.PublicationHeadObservation{<redacted>}")
}

func (o PublicationHeadObservation) Validate() error {
	bound := o.requestIdentity != "" || o.resolverID != "" || o.observedAtMillis != 0
	if bound && (!validCandidateDigest(o.requestIdentity) || ValidatePublisherID(o.resolverID) != nil || !validPublicationHeadMillis(o.observedAtMillis)) {
		return ErrInvalidPublicationHeadObservation
	}
	if !bound && (o.requestIdentity != "" || o.resolverID != "" || o.observedAtMillis != 0) {
		return ErrInvalidPublicationHeadObservation
	}
	switch o.status {
	case PublicationHeadResolved:
		if _, err := canonicalPublicationRevision(o.currentHead); err != nil || o.failure != 0 {
			return ErrInvalidPublicationHeadObservation
		}
	case PublicationHeadResolutionFailed:
		if o.currentHead.Identity() != "" || o.failure.String() == "" {
			return ErrInvalidPublicationHeadObservation
		}
	default:
		return ErrInvalidPublicationHeadObservation
	}
	if o.identity != derivePublicationHeadObservationIdentity(o) {
		return ErrInvalidPublicationHeadObservationIdentity
	}
	return nil
}

// ResolvePublicationHead invokes only the target publisher's resolver after exact authorization checks.
func ResolvePublicationHead(
	ctx context.Context,
	resolver HeadResolver,
	scope audit.ReviewScope,
	authorization PublicationAuthorization,
	claim PublicationClaim,
	attempt PublicationAttemptAuthorization,
	observedAt time.Time,
) (PublicationHeadObservation, error) {
	if isNilPublicationInterface(ctx) {
		return PublicationHeadObservation{}, ErrInvalidPublisherContext
	}
	if err := ctx.Err(); err != nil {
		return PublicationHeadObservation{}, fmt.Errorf("%w: %v", ErrPublisherContextDone, err)
	}
	if isNilPublicationInterface(resolver) {
		return PublicationHeadObservation{}, ErrInvalidHeadResolver
	}
	request, err := newPublicationHeadRequest(scope, authorization, claim, attempt)
	if err != nil {
		return PublicationHeadObservation{}, err
	}
	if !authorization.Authorizes(request.Target(), observedAt) {
		return PublicationHeadObservation{}, ErrPublicationNotAuthorized
	}
	if !attempt.Ready(observedAt) {
		return PublicationHeadObservation{}, ErrPublicationRetryNotAllowed
	}
	if resolver.ResolverID() != request.Target().PublisherID() || !nonzeroPublicationAuthority(resolver.ConfigurationIdentity()) {
		return PublicationHeadObservation{}, ErrPublicationHeadResolverMismatch
	}
	observation := resolver.ResolveHead(ctx, request)
	if err := ctx.Err(); err != nil {
		return PublicationHeadObservation{}, fmt.Errorf("%w: %v", ErrPublisherContextDone, err)
	}
	if err := observation.Validate(); err != nil || observation.RequestIdentity() != "" || observation.ResolverID() != "" || observation.observedAtMillis != 0 {
		return PublicationHeadObservation{}, ErrInvalidPublicationHeadObservation
	}
	observation.requestIdentity = request.Identity()
	observation.resolverID = resolver.ResolverID()
	observation.observedAtMillis = observedAt.UnixMilli()
	observation.identity = derivePublicationHeadObservationIdentity(observation)
	if err := observation.Validate(); err != nil {
		return PublicationHeadObservation{}, err
	}
	return observation, nil
}

// PublicationHeadStatus is the host's comparison result.
type PublicationHeadStatus uint8

const (
	PublicationHeadCurrent PublicationHeadStatus = iota + 1
	PublicationHeadStale
	PublicationHeadUnavailable
)

func (s PublicationHeadStatus) String() string {
	switch s {
	case PublicationHeadCurrent:
		return "current"
	case PublicationHeadStale:
		return "stale"
	case PublicationHeadUnavailable:
		return "unavailable"
	default:
		return ""
	}
}

// PublicationHeadReconciliation binds the expected and observed moving head.
type PublicationHeadReconciliation struct {
	identity              string
	authorizationIdentity string
	claimIdentity         string
	attemptIdentity       string
	targetIdentity        string
	observationIdentity   string
	expectedHeadIdentity  string
	observedHeadIdentity  string
	status                PublicationHeadStatus
	observedAtMillis      int64
	evaluatedAtMillis     int64
}

func ReconcilePublicationHead(
	scope audit.ReviewScope,
	authorization PublicationAuthorization,
	claim PublicationClaim,
	attempt PublicationAttemptAuthorization,
	observation PublicationHeadObservation,
	evaluatedAt time.Time,
) (PublicationHeadReconciliation, error) {
	request, err := newPublicationHeadRequest(scope, authorization, claim, attempt)
	if err != nil || observation.Validate() != nil || observation.RequestIdentity() != request.Identity() || observation.ResolverID() != request.Target().PublisherID() {
		return PublicationHeadReconciliation{}, ErrInvalidPublicationHeadReconciliation
	}
	evaluatedAtMillis := evaluatedAt.UnixMilli()
	age := evaluatedAtMillis - observation.observedAtMillis
	if age < 0 || age > maxPublicationHeadAgeMilliseconds || !authorization.Authorizes(request.Target(), evaluatedAt) {
		return PublicationHeadReconciliation{}, ErrInvalidPublicationHeadReconciliation
	}
	status := PublicationHeadUnavailable
	observedHeadIdentity := ""
	if observation.Status() == PublicationHeadResolved {
		observedHeadIdentity = observation.CurrentHead().Identity()
		status = PublicationHeadStale
		if observedHeadIdentity == request.Target().HeadRevision().Identity() {
			status = PublicationHeadCurrent
		}
	}
	reconciliation := PublicationHeadReconciliation{
		authorizationIdentity: authorization.Identity(), claimIdentity: claim.Identity(), attemptIdentity: attempt.Identity(), targetIdentity: request.Target().Identity(),
		observationIdentity: observation.Identity(), expectedHeadIdentity: request.Target().HeadRevision().Identity(),
		observedHeadIdentity: observedHeadIdentity, status: status,
		observedAtMillis: observation.observedAtMillis, evaluatedAtMillis: evaluatedAtMillis,
	}
	reconciliation.identity = derivePublicationHeadReconciliationIdentity(reconciliation)
	if err := reconciliation.Validate(); err != nil {
		return PublicationHeadReconciliation{}, err
	}
	return reconciliation, nil
}

func (r PublicationHeadReconciliation) Identity() string              { return r.identity }
func (r PublicationHeadReconciliation) AuthorizationIdentity() string { return r.authorizationIdentity }
func (r PublicationHeadReconciliation) ClaimIdentity() string         { return r.claimIdentity }
func (r PublicationHeadReconciliation) AttemptIdentity() string       { return r.attemptIdentity }
func (r PublicationHeadReconciliation) TargetIdentity() string        { return r.targetIdentity }
func (r PublicationHeadReconciliation) ObservationIdentity() string   { return r.observationIdentity }
func (r PublicationHeadReconciliation) Status() PublicationHeadStatus { return r.status }
func (r PublicationHeadReconciliation) ObservedAt() time.Time {
	return time.UnixMilli(r.observedAtMillis).UTC()
}
func (r PublicationHeadReconciliation) EvaluatedAt() time.Time {
	return time.UnixMilli(r.evaluatedAtMillis).UTC()
}
func (r PublicationHeadReconciliation) AuthorizesPublication() bool {
	return r.status == PublicationHeadCurrent && r.Validate() == nil
}
func (r PublicationHeadReconciliation) String() string { return "publication head reconciliation" }
func (r PublicationHeadReconciliation) GoString() string {
	return "review.PublicationHeadReconciliation{<redacted>}"
}
func (r PublicationHeadReconciliation) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication head reconciliation", "review.PublicationHeadReconciliation{<redacted>}")
}

func (r PublicationHeadReconciliation) Validate() error {
	for _, identity := range []string{r.authorizationIdentity, r.claimIdentity, r.attemptIdentity, r.targetIdentity, r.observationIdentity, r.expectedHeadIdentity} {
		if !validCandidateDigest(identity) {
			return ErrInvalidPublicationHeadReconciliation
		}
	}
	validStatus := r.status.String() != ""
	validObservedAt := validPublicationHeadMillis(r.observedAtMillis)
	validEvaluatedAt := validPublicationHeadMillis(r.evaluatedAtMillis)
	age := r.evaluatedAtMillis - r.observedAtMillis
	if !validStatus || !validObservedAt || !validEvaluatedAt || age < 0 || age > maxPublicationHeadAgeMilliseconds {
		return ErrInvalidPublicationHeadReconciliation
	}
	switch r.status {
	case PublicationHeadCurrent:
		if r.observedHeadIdentity != r.expectedHeadIdentity {
			return ErrInvalidPublicationHeadReconciliation
		}
	case PublicationHeadStale:
		if !validCandidateDigest(r.observedHeadIdentity) || r.observedHeadIdentity == r.expectedHeadIdentity {
			return ErrInvalidPublicationHeadReconciliation
		}
	case PublicationHeadUnavailable:
		if r.observedHeadIdentity != "" {
			return ErrInvalidPublicationHeadReconciliation
		}
	}
	if r.identity != derivePublicationHeadReconciliationIdentity(r) {
		return ErrInvalidPublicationHeadReconciliationIdentity
	}
	return nil
}

// PublicationHeadGate proves that the exact reconciliation was appended after the claim.
type PublicationHeadGate struct {
	identity       string
	event          audit.Event
	reconciliation PublicationHeadReconciliation
}

func RecordPublicationHeadReconciliation(
	ctx context.Context,
	ledger audit.Ledger,
	scope audit.ReviewScope,
	authorization PublicationAuthorization,
	claim PublicationClaim,
	attempt PublicationAttemptAuthorization,
	reconciliation PublicationHeadReconciliation,
	occurredAt time.Time,
) (PublicationHeadGate, error) {
	if isNilModelAuditLedger(ledger) {
		return PublicationHeadGate{}, ErrInvalidModelPipelineAuditLedger
	}
	if err := scope.Validate(); err != nil {
		return PublicationHeadGate{}, err
	}
	if err := reconciliation.Validate(); err != nil {
		return PublicationHeadGate{}, err
	}
	if authorization.Plan().ReviewScopeIdentity() != scope.Identity() || claim.ReviewScopeIdentity() != scope.Identity() {
		return PublicationHeadGate{}, ErrPublicationAuditScopeMismatch
	}
	matchingAuthorization := reconciliation.AuthorizationIdentity() == authorization.Identity()
	matchingClaim := reconciliation.ClaimIdentity() == claim.Identity()
	matchingAttempt := reconciliation.AttemptIdentity() == attempt.Identity()
	matchingTarget := reconciliation.TargetIdentity() == authorization.TargetIdentity()
	if !matchingAuthorization || !matchingClaim || !matchingAttempt || !matchingTarget {
		return PublicationHeadGate{}, ErrInvalidPublicationHeadReconciliation
	}
	recordAge := occurredAt.UnixMilli() - reconciliation.EvaluatedAt().UnixMilli()
	if recordAge < 0 || recordAge > maxPublicationHeadAgeMilliseconds || !authorization.Authorizes(authorization.Plan().Target(), occurredAt) {
		return PublicationHeadGate{}, ErrInvalidPublicationHeadReconciliation
	}
	claimEvent, found, err := findModelAuditEvent(ctx, ledger, scope, audit.EventPublicationClaimed, authorization.Identity())
	if err != nil {
		return PublicationHeadGate{}, err
	}
	if !found || claimEvent.Identity() != claim.EventIdentity() {
		return PublicationHeadGate{}, ErrInvalidPublicationClaim
	}
	parents := publicationHeadGateParents(authorization, claim, attempt, reconciliation)
	event, err := appendUniquePublicationHeadEvent(ctx, ledger, scope, attempt.Identity(), reconciliation.Identity(), parents, occurredAt)
	if err != nil {
		return PublicationHeadGate{}, err
	}
	gate := PublicationHeadGate{event: event, reconciliation: reconciliation}
	gate.identity = derivePublicationHeadGateIdentity(gate)
	if err := gate.Validate(); err != nil {
		return PublicationHeadGate{}, err
	}
	return gate, nil
}

func appendUniquePublicationHeadEvent(
	ctx context.Context,
	ledger audit.Ledger,
	scope audit.ReviewScope,
	attemptIdentity string,
	reconciliationIdentity string,
	parents []string,
	occurredAt time.Time,
) (audit.Event, error) {
	for range maxModelPipelineAuditConflicts {
		before, hadBefore, err := ledger.Head(ctx, scope)
		if err != nil {
			return audit.Event{}, err
		}
		existing, same, conflict, err := inspectPublicationHeadEvents(ctx, ledger, scope, attemptIdentity, reconciliationIdentity)
		if err != nil {
			return audit.Event{}, err
		}
		if same {
			if !slices.Equal(existing.CausalParentIdentities(), parents) {
				return audit.Event{}, ErrPublicationHeadReconciliationConflict
			}
			return existing, nil
		}
		if conflict {
			return audit.Event{}, ErrPublicationHeadReconciliationConflict
		}
		head, hasHead, err := ledger.Head(ctx, scope)
		if err != nil {
			return audit.Event{}, err
		}
		if hadBefore != hasHead || hadBefore && before.Identity() != head.Identity() {
			continue
		}
		sequence, previous := uint64(1), ""
		if hasHead {
			sequence, previous = head.Sequence()+1, head.Identity()
		}
		event, err := audit.NewEvent(scope, sequence, previous, audit.EventPublicationHeadReconciled, reconciliationIdentity, parents, occurredAt)
		if err != nil {
			return audit.Event{}, err
		}
		if err := ledger.Append(ctx, previous, event); err == nil {
			return event, nil
		} else if !errors.Is(err, audit.ErrAuditHeadConflict) {
			return audit.Event{}, err
		}
	}
	return audit.Event{}, ErrPublicationHeadReconciliationConflict
}

func inspectPublicationHeadEvents(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, attemptIdentity, reconciliationIdentity string) (audit.Event, bool, bool, error) {
	var after uint64
	for {
		events, err := ledger.Read(ctx, scope, after, 1_000)
		if err != nil {
			return audit.Event{}, false, false, err
		}
		for _, event := range events {
			if event.Kind() != audit.EventPublicationHeadReconciled {
				continue
			}
			if event.SubjectIdentity() == reconciliationIdentity {
				return event, true, false, nil
			}
			if auditEventHasReference(event, attemptIdentity) {
				return audit.Event{}, false, true, nil
			}
		}
		if len(events) < 1_000 {
			return audit.Event{}, false, false, nil
		}
		after = events[len(events)-1].Sequence()
	}
}

func publicationHeadGateParents(authorization PublicationAuthorization, claim PublicationClaim, attempt PublicationAttemptAuthorization, reconciliation PublicationHeadReconciliation) []string {
	parents := []string{authorization.Identity(), claim.Identity(), attempt.Identity(), authorization.TargetIdentity(), reconciliation.ObservationIdentity()}
	sort.Strings(parents)
	return parents
}

func (g PublicationHeadGate) Identity() string                              { return g.identity }
func (g PublicationHeadGate) EventIdentity() string                         { return g.event.Identity() }
func (g PublicationHeadGate) Reconciliation() PublicationHeadReconciliation { return g.reconciliation }
func (g PublicationHeadGate) AuthorizesPublication() bool {
	return g.Validate() == nil && g.reconciliation.AuthorizesPublication()
}
func (g PublicationHeadGate) String() string   { return "publication head gate" }
func (g PublicationHeadGate) GoString() string { return "review.PublicationHeadGate{<redacted>}" }
func (g PublicationHeadGate) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication head gate", "review.PublicationHeadGate{<redacted>}")
}
func (g PublicationHeadGate) Validate() error {
	if err := g.event.Validate(); err != nil || g.reconciliation.Validate() != nil {
		return ErrInvalidPublicationHeadGate
	}
	expectedParents := []string{
		g.reconciliation.AuthorizationIdentity(), g.reconciliation.ClaimIdentity(), g.reconciliation.AttemptIdentity(),
		g.reconciliation.TargetIdentity(), g.reconciliation.ObservationIdentity(),
	}
	sort.Strings(expectedParents)
	if g.event.Kind() != audit.EventPublicationHeadReconciled || g.event.SubjectIdentity() != g.reconciliation.Identity() || !slices.Equal(g.event.CausalParentIdentities(), expectedParents) {
		return ErrInvalidPublicationHeadGate
	}
	if g.identity != derivePublicationHeadGateIdentity(g) {
		return ErrInvalidPublicationHeadGateIdentity
	}
	return nil
}

func canonicalPublicationRevision(revision evidence.RevisionIdentity) (evidence.RevisionIdentity, error) {
	canonical, err := evidence.NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || canonical != revision {
		return evidence.RevisionIdentity{}, ErrInvalidPublicationHeadObservation
	}
	return canonical, nil
}
func validPublicationHeadMillis(value int64) bool {
	return value > 0 && value <= maxPublicationHeadUnixMilliseconds
}

func derivePublicationHeadRequestIdentity(request PublicationHeadRequest) string {
	preimage := struct {
		Contract      string `json:"contract"`
		Version       int    `json:"version"`
		Scope         string `json:"scope"`
		Target        string `json:"target"`
		Authorization string `json:"authorization"`
		Claim         string `json:"claim"`
		Attempt       string `json:"attempt"`
	}{
		Contract: "open-trestle/publication-head-request", Version: 1,
		Scope: request.reviewScopeIdentity, Target: request.target.Identity(), Authorization: request.authorizationIdentity, Claim: request.claimIdentity, Attempt: request.attemptIdentity,
	}
	return hashPublicationHeadValue(preimage)
}
func derivePublicationHeadObservationIdentity(observation PublicationHeadObservation) string {
	preimage := struct {
		Contract   string `json:"contract"`
		Version    int    `json:"version"`
		Request    string `json:"request"`
		Resolver   string `json:"resolver"`
		Status     string `json:"status"`
		Head       string `json:"head"`
		Failure    string `json:"failure"`
		ObservedAt int64  `json:"observed_at"`
	}{
		Contract: "open-trestle/publication-head-observation", Version: 1,
		Request: observation.requestIdentity, Resolver: observation.resolverID,
		Status: observation.status.String(), Head: observation.currentHead.Identity(),
		Failure: observation.failure.String(), ObservedAt: observation.observedAtMillis,
	}
	return hashPublicationHeadValue(preimage)
}
func derivePublicationHeadReconciliationIdentity(value PublicationHeadReconciliation) string {
	preimage := struct {
		Contract      string `json:"contract"`
		Version       int    `json:"version"`
		Authorization string `json:"authorization"`
		Claim         string `json:"claim"`
		Attempt       string `json:"attempt"`
		Target        string `json:"target"`
		Observation   string `json:"observation"`
		Expected      string `json:"expected"`
		Observed      string `json:"observed"`
		Status        string `json:"status"`
		ObservedAt    int64  `json:"observed_at"`
		EvaluatedAt   int64  `json:"evaluated_at"`
	}{
		Contract: "open-trestle/publication-head-reconciliation", Version: 1,
		Authorization: value.authorizationIdentity, Claim: value.claimIdentity, Attempt: value.attemptIdentity,
		Target: value.targetIdentity, Observation: value.observationIdentity,
		Expected: value.expectedHeadIdentity, Observed: value.observedHeadIdentity,
		Status: value.status.String(), ObservedAt: value.observedAtMillis, EvaluatedAt: value.evaluatedAtMillis,
	}
	return hashPublicationHeadValue(preimage)
}
func derivePublicationHeadGateIdentity(gate PublicationHeadGate) string {
	preimage := struct {
		Contract       string `json:"contract"`
		Version        int    `json:"version"`
		Event          string `json:"event"`
		Reconciliation string `json:"reconciliation"`
	}{
		Contract: "open-trestle/publication-head-gate", Version: 1,
		Event: gate.event.Identity(), Reconciliation: gate.reconciliation.Identity(),
	}
	return hashPublicationHeadValue(preimage)
}
func hashPublicationHeadValue(value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
