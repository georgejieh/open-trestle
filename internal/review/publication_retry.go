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
)

const maxPublicationAttempts uint8 = 5

var (
	// ErrInvalidPublicationRetryPolicy identifies unusable attempt or delay limits.
	ErrInvalidPublicationRetryPolicy = errors.New("invalid publication retry policy")
	// ErrInvalidPublicationRetryPolicyIdentity identifies policy content inconsistent with its identity.
	ErrInvalidPublicationRetryPolicyIdentity = errors.New("invalid publication retry policy identity")
	// ErrInvalidPublicationAttempt identifies malformed operation lineage or attempt bounds.
	ErrInvalidPublicationAttempt = errors.New("invalid publication attempt authorization")
	// ErrInvalidPublicationAttemptIdentity identifies attempt content inconsistent with its identity.
	ErrInvalidPublicationAttemptIdentity = errors.New("invalid publication attempt authorization identity")
	// ErrPublicationResultAttemptMismatch identifies a result from another attempt.
	ErrPublicationResultAttemptMismatch = errors.New("publication result attempt mismatch")
	// ErrPublicationResultNotFailed identifies retry evaluation of a successful result.
	ErrPublicationResultNotFailed = errors.New("publication result is not failed")
	// ErrInvalidPublicationRetryDecision identifies malformed retry lineage or semantics.
	ErrInvalidPublicationRetryDecision = errors.New("invalid publication retry decision")
	// ErrInvalidPublicationRetryDecisionIdentity identifies decision content inconsistent with its identity.
	ErrInvalidPublicationRetryDecisionIdentity = errors.New("invalid publication retry decision identity")
	// ErrPublicationRetryNotAllowed identifies a denied or premature retry.
	ErrPublicationRetryNotAllowed = errors.New("publication retry is not allowed")
	// ErrPublicationRetryNotRecorded identifies retry before its failed result is in the ledger.
	ErrPublicationRetryNotRecorded = errors.New("publication retry is not recorded")
	// ErrPublicationRetryConflict identifies competing retry decisions for one attempt.
	ErrPublicationRetryConflict = errors.New("publication retry conflict")
	// ErrInvalidPublicationRetryGate identifies malformed audited retry authority.
	ErrInvalidPublicationRetryGate = errors.New("invalid publication retry gate")
	// ErrInvalidPublicationRetryGateIdentity identifies gate content inconsistent with its identity.
	ErrInvalidPublicationRetryGateIdentity = errors.New("invalid publication retry gate identity")
)

// PublicationRetryPolicy bounds automatic retries for one idempotent publication operation.
type PublicationRetryPolicy struct {
	identity                   string
	maxAttempts                uint8
	transientDelayMilliseconds uint32
	maxRetryDelayMilliseconds  uint32
}

func NewPublicationRetryPolicy(maxAttempts uint8, transientDelayMilliseconds, maxRetryDelayMilliseconds uint32) (PublicationRetryPolicy, error) {
	policy := PublicationRetryPolicy{maxAttempts: maxAttempts, transientDelayMilliseconds: transientDelayMilliseconds, maxRetryDelayMilliseconds: maxRetryDelayMilliseconds}
	if err := policy.validateFields(); err != nil {
		return PublicationRetryPolicy{}, err
	}
	policy.identity = derivePublicationRetryPolicyIdentity(policy)
	return policy, nil
}
func (p PublicationRetryPolicy) Identity() string   { return p.identity }
func (p PublicationRetryPolicy) MaxAttempts() uint8 { return p.maxAttempts }
func (p PublicationRetryPolicy) TransientDelayMilliseconds() uint32 {
	return p.transientDelayMilliseconds
}
func (p PublicationRetryPolicy) MaxRetryDelayMilliseconds() uint32 {
	return p.maxRetryDelayMilliseconds
}
func (p PublicationRetryPolicy) Validate() error {
	if err := p.validateFields(); err != nil {
		return err
	}
	if p.identity != derivePublicationRetryPolicyIdentity(p) {
		return ErrInvalidPublicationRetryPolicyIdentity
	}
	return nil
}
func (p PublicationRetryPolicy) validateFields() error {
	if p.maxAttempts == 0 || p.maxAttempts > maxPublicationAttempts || p.maxRetryDelayMilliseconds > maxPublicationRetryAfterMilliseconds || p.transientDelayMilliseconds > p.maxRetryDelayMilliseconds {
		return ErrInvalidPublicationRetryPolicy
	}
	return nil
}
func (p PublicationRetryPolicy) String() string   { return "publication retry policy" }
func (p PublicationRetryPolicy) GoString() string { return "review.PublicationRetryPolicy{<redacted>}" }
func (p PublicationRetryPolicy) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication retry policy", "review.PublicationRetryPolicy{<redacted>}")
}

// PublicationAttemptKind identifies the initial or explicitly retried dispatch.
type PublicationAttemptKind uint8

const (
	PublicationAttemptInitial PublicationAttemptKind = iota + 1
	PublicationAttemptRetry
)

func (k PublicationAttemptKind) String() string {
	if k == PublicationAttemptInitial {
		return "initial"
	}
	if k == PublicationAttemptRetry {
		return "retry"
	}
	return ""
}

// PublicationAttemptAuthorization binds one bounded dispatch to the operation claim.
type PublicationAttemptAuthorization struct {
	identity              string
	kind                  PublicationAttemptKind
	authorizationIdentity string
	claimIdentity         string
	attemptNumber         uint8
	priorAttemptIdentity  string
	retryGateIdentity     string
	notBeforeMilliseconds int64
}

func NewInitialPublicationAttemptAuthorization(authorization PublicationAuthorization, claim PublicationClaim) (PublicationAttemptAuthorization, error) {
	if err := validatePublicationOperationBinding(authorization, claim); err != nil {
		return PublicationAttemptAuthorization{}, err
	}
	attempt := PublicationAttemptAuthorization{kind: PublicationAttemptInitial, authorizationIdentity: authorization.Identity(), claimIdentity: claim.Identity(), attemptNumber: 1}
	attempt.identity = derivePublicationAttemptIdentity(attempt)
	return attempt, nil
}
func NewRetryPublicationAttemptAuthorization(
	authorization PublicationAuthorization,
	claim PublicationClaim,
	prior PublicationAttemptAuthorization,
	gate PublicationRetryGate,
) (PublicationAttemptAuthorization, error) {
	if err := validatePublicationOperationBinding(authorization, claim); err != nil {
		return PublicationAttemptAuthorization{}, err
	}
	if err := prior.Validate(); err != nil {
		return PublicationAttemptAuthorization{}, err
	}
	if err := gate.Validate(); err != nil {
		return PublicationAttemptAuthorization{}, err
	}
	decision := gate.Decision()
	matchingPrior := prior.Identity() == decision.AttemptIdentity()
	matchingAuthorization := decision.AuthorizationIdentity() == authorization.Identity()
	matchingClaim := decision.ClaimIdentity() == claim.Identity()
	matchingNumber := decision.NextAttemptNumber() == prior.AttemptNumber()+1
	if !gate.AuthorizesRetry() || !matchingPrior || !matchingAuthorization || !matchingClaim || !matchingNumber {
		return PublicationAttemptAuthorization{}, ErrPublicationRetryNotAllowed
	}
	attempt := PublicationAttemptAuthorization{
		kind: PublicationAttemptRetry, authorizationIdentity: authorization.Identity(),
		claimIdentity: claim.Identity(), attemptNumber: decision.NextAttemptNumber(),
		priorAttemptIdentity: prior.Identity(), retryGateIdentity: gate.Identity(),
		notBeforeMilliseconds: decision.notBeforeMilliseconds,
	}
	attempt.identity = derivePublicationAttemptIdentity(attempt)
	return attempt, nil
}
func (a PublicationAttemptAuthorization) Identity() string             { return a.identity }
func (a PublicationAttemptAuthorization) Kind() PublicationAttemptKind { return a.kind }
func (a PublicationAttemptAuthorization) AuthorizationIdentity() string {
	return a.authorizationIdentity
}
func (a PublicationAttemptAuthorization) ClaimIdentity() string        { return a.claimIdentity }
func (a PublicationAttemptAuthorization) AttemptNumber() uint8         { return a.attemptNumber }
func (a PublicationAttemptAuthorization) PriorAttemptIdentity() string { return a.priorAttemptIdentity }
func (a PublicationAttemptAuthorization) RetryGateIdentity() string    { return a.retryGateIdentity }
func (a PublicationAttemptAuthorization) NotBefore() time.Time {
	return time.UnixMilli(a.notBeforeMilliseconds).UTC()
}
func (a PublicationAttemptAuthorization) Ready(at time.Time) bool {
	return a.Validate() == nil && (a.kind == PublicationAttemptInitial || at.UnixMilli() >= a.notBeforeMilliseconds)
}
func (a PublicationAttemptAuthorization) Validate() error {
	if !validCandidateDigest(a.authorizationIdentity) || !validCandidateDigest(a.claimIdentity) || a.attemptNumber == 0 || a.attemptNumber > maxPublicationAttempts {
		return ErrInvalidPublicationAttempt
	}
	switch a.kind {
	case PublicationAttemptInitial:
		if a.attemptNumber != 1 || a.priorAttemptIdentity != "" || a.retryGateIdentity != "" || a.notBeforeMilliseconds != 0 {
			return ErrInvalidPublicationAttempt
		}
	case PublicationAttemptRetry:
		if a.attemptNumber < 2 || !validCandidateDigest(a.priorAttemptIdentity) || !validCandidateDigest(a.retryGateIdentity) || !validPublicationHeadMillis(a.notBeforeMilliseconds) {
			return ErrInvalidPublicationAttempt
		}
	default:
		return ErrInvalidPublicationAttempt
	}
	if a.identity != derivePublicationAttemptIdentity(a) {
		return ErrInvalidPublicationAttemptIdentity
	}
	return nil
}
func (a PublicationAttemptAuthorization) String() string { return "publication attempt authorization" }
func (a PublicationAttemptAuthorization) GoString() string {
	return "review.PublicationAttemptAuthorization{<redacted>}"
}
func (a PublicationAttemptAuthorization) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication attempt authorization", "review.PublicationAttemptAuthorization{<redacted>}")
}

func validatePublicationOperationBinding(authorization PublicationAuthorization, claim PublicationClaim) error {
	if err := authorization.Validate(); err != nil {
		return err
	}
	if err := claim.Validate(); err != nil {
		return err
	}
	matchingAuthorization := claim.AuthorizationIdentity() == authorization.Identity()
	matchingPlan := claim.PlanIdentity() == authorization.PlanIdentity()
	matchingTarget := claim.TargetIdentity() == authorization.TargetIdentity()
	matchingKey := claim.IdempotencyKey() == authorization.IdempotencyKey()
	if !matchingAuthorization || !matchingPlan || !matchingTarget || !matchingKey {
		return ErrInvalidPublicationAttempt
	}
	return nil
}

// PublicationRetryReason explains one closed retry decision.
type PublicationRetryReason uint8

const (
	PublicationRetryTransient PublicationRetryReason = iota + 1
	PublicationRetryRateLimited
	PublicationRetryAttemptLimit
	PublicationRetryPermanentFailure
	PublicationRetryDelayLimit
)

func (r PublicationRetryReason) String() string {
	switch r {
	case PublicationRetryTransient:
		return "transient"
	case PublicationRetryRateLimited:
		return "rate_limited"
	case PublicationRetryAttemptLimit:
		return "attempt_limit"
	case PublicationRetryPermanentFailure:
		return "permanent_failure"
	case PublicationRetryDelayLimit:
		return "delay_limit"
	default:
		return ""
	}
}

// PublicationRetryDecision binds policy, failed attempt, result, and bounded delay.
type PublicationRetryDecision struct {
	identity, policyIdentity, authorizationIdentity, claimIdentity, attemptIdentity, resultIdentity string
	allowed                                                                                         bool
	reason                                                                                          PublicationRetryReason
	delayMilliseconds                                                                               uint32
	nextAttemptNumber                                                                               uint8
	evaluatedAtMilliseconds                                                                         int64
	notBeforeMilliseconds                                                                           int64
}

func EvaluatePublicationRetry(policy PublicationRetryPolicy, attempt PublicationAttemptAuthorization, result PublicationResult, evaluatedAt time.Time) (PublicationRetryDecision, error) {
	if err := policy.Validate(); err != nil {
		return PublicationRetryDecision{}, err
	}
	if err := attempt.Validate(); err != nil {
		return PublicationRetryDecision{}, err
	}
	if err := result.Validate(); err != nil {
		return PublicationRetryDecision{}, err
	}
	if result.AttemptIdentity() != attempt.Identity() {
		return PublicationRetryDecision{}, ErrPublicationResultAttemptMismatch
	}
	if result.Status() != PublicationFailed {
		return PublicationRetryDecision{}, ErrPublicationResultNotFailed
	}
	decision := PublicationRetryDecision{
		evaluatedAtMilliseconds: evaluatedAt.UnixMilli(), policyIdentity: policy.Identity(),
		authorizationIdentity: attempt.AuthorizationIdentity(), claimIdentity: attempt.ClaimIdentity(),
		attemptIdentity: attempt.Identity(), resultIdentity: result.Identity(),
		nextAttemptNumber: attempt.AttemptNumber() + 1,
	}
	switch {
	case attempt.AttemptNumber() >= policy.MaxAttempts():
		decision.reason = PublicationRetryAttemptLimit
		decision.nextAttemptNumber = 0
	case result.Failure() == PublicationFailureTransient || result.Failure() == PublicationFailureCancelled:
		decision.allowed = true
		decision.reason = PublicationRetryTransient
		decision.delayMilliseconds = policy.TransientDelayMilliseconds()
	case result.Failure() == PublicationFailureRateLimited:
		decision.reason = PublicationRetryRateLimited
		decision.delayMilliseconds = result.RetryAfterMilliseconds()
		if decision.delayMilliseconds == 0 {
			decision.delayMilliseconds = policy.TransientDelayMilliseconds()
		}
		if decision.delayMilliseconds <= policy.MaxRetryDelayMilliseconds() {
			decision.allowed = true
		} else {
			decision.reason = PublicationRetryDelayLimit
			decision.delayMilliseconds = 0
			decision.nextAttemptNumber = 0
		}
	default:
		decision.reason = PublicationRetryPermanentFailure
		decision.nextAttemptNumber = 0
	}
	if decision.allowed {
		decision.notBeforeMilliseconds = decision.evaluatedAtMilliseconds + int64(decision.delayMilliseconds)
	}
	decision.identity = derivePublicationRetryDecisionIdentity(decision)
	if err := decision.Validate(); err != nil {
		return PublicationRetryDecision{}, err
	}
	return decision, nil
}
func (d PublicationRetryDecision) Identity() string               { return d.identity }
func (d PublicationRetryDecision) PolicyIdentity() string         { return d.policyIdentity }
func (d PublicationRetryDecision) AuthorizationIdentity() string  { return d.authorizationIdentity }
func (d PublicationRetryDecision) ClaimIdentity() string          { return d.claimIdentity }
func (d PublicationRetryDecision) AttemptIdentity() string        { return d.attemptIdentity }
func (d PublicationRetryDecision) ResultIdentity() string         { return d.resultIdentity }
func (d PublicationRetryDecision) Allowed() bool                  { return d.allowed }
func (d PublicationRetryDecision) Reason() PublicationRetryReason { return d.reason }
func (d PublicationRetryDecision) DelayMilliseconds() uint32      { return d.delayMilliseconds }
func (d PublicationRetryDecision) NextAttemptNumber() uint8       { return d.nextAttemptNumber }
func (d PublicationRetryDecision) EvaluatedAt() time.Time {
	return time.UnixMilli(d.evaluatedAtMilliseconds).UTC()
}
func (d PublicationRetryDecision) NotBefore() time.Time {
	return time.UnixMilli(d.notBeforeMilliseconds).UTC()
}
func (d PublicationRetryDecision) Validate() error {
	for _, id := range []string{d.policyIdentity, d.authorizationIdentity, d.claimIdentity, d.attemptIdentity, d.resultIdentity} {
		if !validCandidateDigest(id) {
			return ErrInvalidPublicationRetryDecision
		}
	}
	if d.reason.String() == "" || !validPublicationHeadMillis(d.evaluatedAtMilliseconds) {
		return ErrInvalidPublicationRetryDecision
	}
	if d.allowed {
		validAttempt := d.nextAttemptNumber >= 2 && d.nextAttemptNumber <= maxPublicationAttempts
		retryableReason := d.reason == PublicationRetryTransient || d.reason == PublicationRetryRateLimited
		validNotBefore := d.notBeforeMilliseconds == d.evaluatedAtMilliseconds+int64(d.delayMilliseconds)
		if !validAttempt || !retryableReason || !validNotBefore || !validPublicationHeadMillis(d.notBeforeMilliseconds) {
			return ErrInvalidPublicationRetryDecision
		}
	} else if d.nextAttemptNumber != 0 || d.delayMilliseconds != 0 || d.notBeforeMilliseconds != 0 {
		return ErrInvalidPublicationRetryDecision
	}
	if d.identity != derivePublicationRetryDecisionIdentity(d) {
		return ErrInvalidPublicationRetryDecisionIdentity
	}
	return nil
}
func (d PublicationRetryDecision) String() string { return "publication retry decision" }
func (d PublicationRetryDecision) GoString() string {
	return "review.PublicationRetryDecision{<redacted>}"
}
func (d PublicationRetryDecision) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication retry decision", "review.PublicationRetryDecision{<redacted>}")
}

// PublicationRetryGate proves an allowed retry decision was appended after its failed result.
type PublicationRetryGate struct {
	identity                string
	event                   audit.Event
	decision                PublicationRetryDecision
	completionEventIdentity string
}

func RecordPublicationRetryDecision(
	ctx context.Context,
	ledger audit.Ledger,
	scope audit.ReviewScope,
	authorization PublicationAuthorization,
	claim PublicationClaim,
	attempt PublicationAttemptAuthorization,
	result PublicationResult,
	decision PublicationRetryDecision,
	occurredAt time.Time,
) (PublicationRetryGate, error) {
	if isNilModelAuditLedger(ledger) {
		return PublicationRetryGate{}, ErrInvalidModelPipelineAuditLedger
	}
	if err := scope.Validate(); err != nil {
		return PublicationRetryGate{}, err
	}
	if err := validatePublicationOperationBinding(authorization, claim); err != nil {
		return PublicationRetryGate{}, err
	}
	if err := attempt.Validate(); err != nil {
		return PublicationRetryGate{}, err
	}
	if err := result.Validate(); err != nil {
		return PublicationRetryGate{}, err
	}
	if err := decision.Validate(); err != nil {
		return PublicationRetryGate{}, err
	}
	if authorization.Plan().ReviewScopeIdentity() != scope.Identity() || claim.ReviewScopeIdentity() != scope.Identity() {
		return PublicationRetryGate{}, ErrPublicationAuditScopeMismatch
	}
	if !decision.Allowed() {
		return PublicationRetryGate{}, ErrPublicationRetryNotAllowed
	}
	matchingAttempt := decision.AttemptIdentity() == attempt.Identity()
	matchingResult := decision.ResultIdentity() == result.Identity()
	matchingAuthorization := decision.AuthorizationIdentity() == authorization.Identity()
	matchingClaim := decision.ClaimIdentity() == claim.Identity()
	if !matchingAttempt || !matchingResult || !matchingAuthorization || !matchingClaim {
		return PublicationRetryGate{}, ErrInvalidPublicationRetryDecision
	}
	if occurredAt.UnixMilli() < decision.evaluatedAtMilliseconds || !authorization.Authorizes(authorization.Plan().Target(), occurredAt) {
		return PublicationRetryGate{}, ErrPublicationRetryNotAllowed
	}
	completion, found, err := findModelAuditEvent(ctx, ledger, scope, audit.EventPublicationCompleted, result.Identity())
	if err != nil {
		return PublicationRetryGate{}, err
	}
	if !found || completion.OccurredAtUnixMilliseconds() > decision.evaluatedAtMilliseconds {
		return PublicationRetryGate{}, ErrPublicationRetryNotRecorded
	}
	parents := []string{authorization.Identity(), claim.Identity(), attempt.Identity(), result.Identity(), completion.Identity(), decision.PolicyIdentity()}
	sort.Strings(parents)
	event, err := appendUniquePublicationRetryEvent(ctx, ledger, scope, attempt.Identity(), decision.Identity(), parents, occurredAt)
	if err != nil {
		return PublicationRetryGate{}, err
	}
	gate := PublicationRetryGate{event: event, decision: decision, completionEventIdentity: completion.Identity()}
	gate.identity = derivePublicationRetryGateIdentity(gate)
	if err := gate.Validate(); err != nil {
		return PublicationRetryGate{}, err
	}
	return gate, nil
}

func appendUniquePublicationRetryEvent(
	ctx context.Context,
	ledger audit.Ledger,
	scope audit.ReviewScope,
	attemptIdentity string,
	decisionIdentity string,
	parents []string,
	occurredAt time.Time,
) (audit.Event, error) {
	for range maxModelPipelineAuditConflicts {
		before, hadBefore, err := ledger.Head(ctx, scope)
		if err != nil {
			return audit.Event{}, err
		}
		existing, same, conflict, err := inspectPublicationRetryEvents(ctx, ledger, scope, attemptIdentity, decisionIdentity)
		if err != nil {
			return audit.Event{}, err
		}
		if same {
			if !slices.Equal(existing.CausalParentIdentities(), parents) {
				return audit.Event{}, ErrPublicationRetryConflict
			}
			return existing, nil
		}
		if conflict {
			return audit.Event{}, ErrPublicationRetryConflict
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
		event, err := audit.NewEvent(scope, sequence, previous, audit.EventPublicationRetryAuthorized, decisionIdentity, parents, occurredAt)
		if err != nil {
			return audit.Event{}, err
		}
		if err := ledger.Append(ctx, previous, event); err == nil {
			return event, nil
		} else if !errors.Is(err, audit.ErrAuditHeadConflict) {
			return audit.Event{}, err
		}
	}
	return audit.Event{}, ErrPublicationRetryConflict
}

func inspectPublicationRetryEvents(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, attemptIdentity, decisionIdentity string) (audit.Event, bool, bool, error) {
	var after uint64
	for {
		events, err := ledger.Read(ctx, scope, after, 1_000)
		if err != nil {
			return audit.Event{}, false, false, err
		}
		for _, event := range events {
			if event.Kind() != audit.EventPublicationRetryAuthorized {
				continue
			}
			if event.SubjectIdentity() == decisionIdentity {
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

func (g PublicationRetryGate) Identity() string                   { return g.identity }
func (g PublicationRetryGate) EventIdentity() string              { return g.event.Identity() }
func (g PublicationRetryGate) Decision() PublicationRetryDecision { return g.decision }
func (g PublicationRetryGate) CompletionEventIdentity() string    { return g.completionEventIdentity }
func (g PublicationRetryGate) AuthorizesRetry() bool {
	return g.Validate() == nil && g.decision.Allowed()
}
func (g PublicationRetryGate) Validate() error {
	if err := g.event.Validate(); err != nil || g.decision.Validate() != nil {
		return ErrInvalidPublicationRetryGate
	}
	parents := []string{
		g.decision.AuthorizationIdentity(), g.decision.ClaimIdentity(), g.decision.AttemptIdentity(),
		g.decision.ResultIdentity(), g.completionEventIdentity, g.decision.PolicyIdentity(),
	}
	sort.Strings(parents)
	validEvent := g.event.Kind() == audit.EventPublicationRetryAuthorized
	matchingSubject := g.event.SubjectIdentity() == g.decision.Identity()
	matchingParents := slices.Equal(g.event.CausalParentIdentities(), parents)
	if !validCandidateDigest(g.completionEventIdentity) || !validEvent || !matchingSubject || !matchingParents {
		return ErrInvalidPublicationRetryGate
	}
	if g.identity != derivePublicationRetryGateIdentity(g) {
		return ErrInvalidPublicationRetryGateIdentity
	}
	return nil
}
func (g PublicationRetryGate) String() string   { return "publication retry gate" }
func (g PublicationRetryGate) GoString() string { return "review.PublicationRetryGate{<redacted>}" }
func (g PublicationRetryGate) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication retry gate", "review.PublicationRetryGate{<redacted>}")
}

func derivePublicationRetryPolicyIdentity(policy PublicationRetryPolicy) string {
	preimage := struct {
		Contract       string `json:"contract"`
		Version        int    `json:"version"`
		MaxAttempts    uint8  `json:"max_attempts"`
		TransientDelay uint32 `json:"transient_delay"`
		MaxDelay       uint32 `json:"max_delay"`
	}{"open-trestle/publication-retry-policy", 1, policy.maxAttempts, policy.transientDelayMilliseconds, policy.maxRetryDelayMilliseconds}
	return hashPublicationRetryValue(preimage)
}
func derivePublicationAttemptIdentity(attempt PublicationAttemptAuthorization) string {
	preimage := struct {
		Contract      string `json:"contract"`
		Version       int    `json:"version"`
		Kind          string `json:"kind"`
		Authorization string `json:"authorization"`
		Claim         string `json:"claim"`
		Number        uint8  `json:"number"`
		Prior         string `json:"prior"`
		Gate          string `json:"gate"`
		NotBefore     int64  `json:"not_before"`
	}{
		"open-trestle/publication-attempt-authorization", 1, attempt.kind.String(), attempt.authorizationIdentity,
		attempt.claimIdentity, attempt.attemptNumber, attempt.priorAttemptIdentity, attempt.retryGateIdentity, attempt.notBeforeMilliseconds,
	}
	return hashPublicationRetryValue(preimage)
}
func derivePublicationRetryDecisionIdentity(decision PublicationRetryDecision) string {
	preimage := struct {
		Contract      string `json:"contract"`
		Version       int    `json:"version"`
		Policy        string `json:"policy"`
		Authorization string `json:"authorization"`
		Claim         string `json:"claim"`
		Attempt       string `json:"attempt"`
		Result        string `json:"result"`
		Allowed       bool   `json:"allowed"`
		Reason        string `json:"reason"`
		Delay         uint32 `json:"delay"`
		Next          uint8  `json:"next"`
		EvaluatedAt   int64  `json:"evaluated_at"`
		NotBefore     int64  `json:"not_before"`
	}{
		"open-trestle/publication-retry-decision", 1, decision.policyIdentity, decision.authorizationIdentity,
		decision.claimIdentity, decision.attemptIdentity, decision.resultIdentity, decision.allowed,
		decision.reason.String(), decision.delayMilliseconds, decision.nextAttemptNumber,
		decision.evaluatedAtMilliseconds, decision.notBeforeMilliseconds,
	}
	return hashPublicationRetryValue(preimage)
}
func derivePublicationRetryGateIdentity(gate PublicationRetryGate) string {
	preimage := struct {
		Contract   string `json:"contract"`
		Version    int    `json:"version"`
		Event      string `json:"event"`
		Decision   string `json:"decision"`
		Completion string `json:"completion"`
	}{"open-trestle/publication-retry-gate", 1, gate.event.Identity(), gate.decision.Identity(), gate.completionEventIdentity}
	return hashPublicationRetryValue(preimage)
}
func hashPublicationRetryValue(value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
