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

var (
	// ErrPublicationAuditScopeMismatch identifies a publication record from another review scope.
	ErrPublicationAuditScopeMismatch = errors.New("publication audit scope mismatch")
	// ErrPublicationReadinessNotRecorded identifies authorization before its readiness audit record.
	ErrPublicationReadinessNotRecorded = errors.New("publication readiness not recorded")
	// ErrPublicationSourceNotRecorded identifies authorization before its acquired source audit record.
	ErrPublicationSourceNotRecorded = errors.New("publication source not recorded")
	// ErrPublicationContextNotRecorded identifies authorization before its acquired context audit record.
	ErrPublicationContextNotRecorded = errors.New("publication context not recorded")
	// ErrPublicationAuthorizationNotRecorded identifies a claim before its authorization audit record.
	ErrPublicationAuthorizationNotRecorded = errors.New("publication authorization not recorded")
	// ErrPublicationClaimConflict identifies another authorization that already claimed the same plan.
	ErrPublicationClaimConflict = errors.New("publication claim conflict")
	// ErrPublicationCompletionConflict identifies a second terminal result for one claim.
	ErrPublicationCompletionConflict = errors.New("publication completion conflict")
	// ErrInvalidPublicationClaim identifies malformed event, target, plan, or idempotency bindings.
	ErrInvalidPublicationClaim = errors.New("invalid publication claim")
	// ErrInvalidPublicationClaimIdentity identifies claim content inconsistent with its identity.
	ErrInvalidPublicationClaimIdentity = errors.New("invalid publication claim identity")
)

// PublicationClaim is the exclusive audited acquisition required before publisher dispatch.
type PublicationClaim struct {
	identity                   string
	event                      audit.Event
	authorizationIdentity      string
	planIdentity               string
	targetIdentity             string
	idempotencyKey             string
	authorizationEventIdentity string
}

// RecordPublicationAuthorization records a live exact-scope grant after publication readiness.
func RecordPublicationAuthorization(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, authorization PublicationAuthorization, occurredAt time.Time) (audit.Event, error) {
	if isNilModelAuditLedger(ledger) {
		return audit.Event{}, ErrInvalidModelPipelineAuditLedger
	}
	if err := scope.Validate(); err != nil {
		return audit.Event{}, err
	}
	if err := authorization.Validate(); err != nil {
		return audit.Event{}, err
	}
	if authorization.Plan().ReviewScopeIdentity() != scope.Identity() {
		return audit.Event{}, ErrPublicationAuditScopeMismatch
	}
	if !authorization.Authorizes(authorization.Plan().Target(), occurredAt) {
		return audit.Event{}, ErrPublicationNotAuthorized
	}
	sourceEvent, sourceFound, err := findModelAuditEvent(ctx, ledger, scope, audit.EventReviewSnapshotBound, authorization.Plan().SourceSnapshotBindingIdentity())
	if err != nil {
		return audit.Event{}, err
	}
	if !sourceFound {
		return audit.Event{}, ErrPublicationSourceNotRecorded
	}
	contextEvent, contextFound, err := findModelAuditEvent(ctx, ledger, scope, audit.EventContextAcquisitionBound, authorization.Plan().AcquiredContextBindingIdentity())
	if err != nil {
		return audit.Event{}, err
	}
	if !contextFound {
		return audit.Event{}, ErrPublicationContextNotRecorded
	}
	matchingSource := auditEventHasReference(contextEvent, authorization.Plan().SourceSnapshotBindingIdentity())
	matchingGeneration := auditEventHasReference(contextEvent, authorization.Plan().GenerationContextIdentity())
	if !matchingSource || !matchingGeneration || contextEvent.Sequence() <= sourceEvent.Sequence() {
		return audit.Event{}, ErrPublicationContextNotRecorded
	}
	readinessEvent, found, err := findModelAuditEvent(ctx, ledger, scope, audit.EventPublicationReadinessEvaluated, authorization.Plan().ReadinessIdentity())
	if err != nil {
		return audit.Event{}, err
	}
	if !found {
		return audit.Event{}, ErrPublicationReadinessNotRecorded
	}
	if sourceEvent.Sequence() >= readinessEvent.Sequence() || sourceEvent.OccurredAtUnixMilliseconds() > readinessEvent.OccurredAtUnixMilliseconds() {
		return audit.Event{}, ErrPublicationSourceNotRecorded
	}
	parents := []string{
		authorization.PlanIdentity(), authorization.EffectAuthorizationIdentity(),
		authorization.Plan().ReadinessIdentity(), readinessEvent.Identity(),
		authorization.Plan().SourceSnapshotBindingIdentity(), sourceEvent.Identity(),
		authorization.Plan().AcquiredContextBindingIdentity(), contextEvent.Identity(),
		authorization.TargetIdentity(),
	}
	return appendUniqueModelAuditEvent(ctx, ledger, scope, modelAuditEventSpecification{
		kind: audit.EventPublicationAuthorized, subject: authorization.Identity(), parents: parents,
	}, occurredAt)
}

// ClaimPublication atomically grants exactly one caller ownership of an authorized plan.
func ClaimPublication(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, authorization PublicationAuthorization, occurredAt time.Time) (PublicationClaim, bool, error) {
	if isNilModelAuditLedger(ledger) {
		return PublicationClaim{}, false, ErrInvalidModelPipelineAuditLedger
	}
	if err := scope.Validate(); err != nil {
		return PublicationClaim{}, false, err
	}
	if err := authorization.Validate(); err != nil {
		return PublicationClaim{}, false, err
	}
	if authorization.Plan().ReviewScopeIdentity() != scope.Identity() {
		return PublicationClaim{}, false, ErrPublicationAuditScopeMismatch
	}
	if !authorization.Authorizes(authorization.Plan().Target(), occurredAt) {
		return PublicationClaim{}, false, ErrPublicationNotAuthorized
	}
	authorizationEvent, found, err := findModelAuditEvent(ctx, ledger, scope, audit.EventPublicationAuthorized, authorization.Identity())
	if err != nil {
		return PublicationClaim{}, false, err
	}
	if !found {
		return PublicationClaim{}, false, ErrPublicationAuthorizationNotRecorded
	}
	parents := publicationClaimParents(authorization, authorizationEvent.Identity())
	for range maxModelPipelineAuditConflicts {
		before, hadBefore, err := ledger.Head(ctx, scope)
		if err != nil {
			return PublicationClaim{}, false, err
		}
		_, sameAuthorization, competingPlan, err := inspectPublicationClaims(ctx, ledger, scope, authorization)
		if err != nil {
			return PublicationClaim{}, false, err
		}
		if sameAuthorization {
			return PublicationClaim{}, false, nil
		}
		if competingPlan {
			return PublicationClaim{}, false, ErrPublicationClaimConflict
		}
		head, hasHead, err := ledger.Head(ctx, scope)
		if err != nil {
			return PublicationClaim{}, false, err
		}
		if hadBefore != hasHead || hadBefore && before.Identity() != head.Identity() {
			continue
		}
		sequence, previous := uint64(1), ""
		if hasHead {
			sequence, previous = head.Sequence()+1, head.Identity()
		}
		event, err := audit.NewEvent(scope, sequence, previous, audit.EventPublicationClaimed, authorization.Identity(), parents, occurredAt)
		if err != nil {
			return PublicationClaim{}, false, err
		}
		if err := ledger.Append(ctx, previous, event); err == nil {
			claim, claimErr := newPublicationClaim(event, authorization)
			return claim, true, claimErr
		} else if !errors.Is(err, audit.ErrAuditHeadConflict) {
			return PublicationClaim{}, false, err
		}
	}
	return PublicationClaim{}, false, ErrPublicationClaimConflict
}

func inspectPublicationClaims(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, authorization PublicationAuthorization) (audit.Event, bool, bool, error) {
	var after uint64
	for {
		events, err := ledger.Read(ctx, scope, after, 1_000)
		if err != nil {
			return audit.Event{}, false, false, err
		}
		for _, event := range events {
			if event.Kind() != audit.EventPublicationClaimed {
				continue
			}
			if event.SubjectIdentity() == authorization.Identity() {
				return event, true, false, nil
			}
			if auditEventHasReference(event, authorization.PlanIdentity()) {
				return audit.Event{}, false, true, nil
			}
		}
		if len(events) < 1_000 {
			return audit.Event{}, false, false, nil
		}
		after = events[len(events)-1].Sequence()
	}
}

func auditEventHasReference(event audit.Event, identity string) bool {
	for _, reference := range event.CausalParentIdentities() {
		if reference == identity {
			return true
		}
	}
	return false
}

func publicationClaimParents(authorization PublicationAuthorization, authorizationEventIdentity string) []string {
	parents := []string{
		authorization.Identity(), authorization.PlanIdentity(),
		authorization.TargetIdentity(), authorization.IdempotencyKey(), authorizationEventIdentity,
	}
	sort.Strings(parents)
	return parents
}

func findAuditParentByExclusion(event audit.Event, authorization PublicationAuthorization) string {
	known := map[string]struct{}{
		authorization.Identity(): {}, authorization.PlanIdentity(): {},
		authorization.TargetIdentity(): {}, authorization.IdempotencyKey(): {},
	}
	for _, parent := range event.CausalParentIdentities() {
		if _, exists := known[parent]; !exists {
			return parent
		}
	}
	return ""
}

func newPublicationClaim(event audit.Event, authorization PublicationAuthorization) (PublicationClaim, error) {
	claim := PublicationClaim{
		event: event, authorizationIdentity: authorization.Identity(), planIdentity: authorization.PlanIdentity(),
		targetIdentity: authorization.TargetIdentity(), idempotencyKey: authorization.IdempotencyKey(), authorizationEventIdentity: findAuditParentByExclusion(event, authorization),
	}
	claim.identity = derivePublicationClaimIdentity(claim)
	if err := claim.Validate(); err != nil {
		return PublicationClaim{}, err
	}
	return claim, nil
}

// RecordPublicationResult appends exactly one terminal result for an acquired claim.
func RecordPublicationResult(
	ctx context.Context,
	ledger audit.Ledger,
	scope audit.ReviewScope,
	authorization PublicationAuthorization,
	claim PublicationClaim,
	attempt PublicationAttemptAuthorization,
	result PublicationResult,
	occurredAt time.Time,
) (audit.Event, error) {
	if isNilModelAuditLedger(ledger) {
		return audit.Event{}, ErrInvalidModelPipelineAuditLedger
	}
	if err := scope.Validate(); err != nil {
		return audit.Event{}, err
	}
	if err := authorization.Validate(); err != nil {
		return audit.Event{}, err
	}
	if err := claim.Validate(); err != nil {
		return audit.Event{}, err
	}
	if err := attempt.Validate(); err != nil {
		return audit.Event{}, err
	}
	if err := result.Validate(); err != nil {
		return audit.Event{}, err
	}
	if authorization.Plan().ReviewScopeIdentity() != scope.Identity() || claim.ReviewScopeIdentity() != scope.Identity() {
		return audit.Event{}, ErrPublicationAuditScopeMismatch
	}
	matchingClaimAuthorization := claim.AuthorizationIdentity() == authorization.Identity()
	matchingResultAuthorization := result.AuthorizationIdentity() == authorization.Identity()
	matchingResultClaim := result.ClaimIdentity() == claim.Identity()
	matchingResultAttempt := result.AttemptIdentity() == attempt.Identity()
	if !matchingClaimAuthorization || !matchingResultAuthorization || !matchingResultClaim || !matchingResultAttempt {
		return audit.Event{}, ErrInvalidPublicationResult
	}
	headEvent, found, err := findModelAuditEvent(ctx, ledger, scope, audit.EventPublicationHeadReconciled, result.HeadReconciliationIdentity())
	if err != nil {
		return audit.Event{}, err
	}
	if !found || occurredAt.UnixMilli() < headEvent.OccurredAtUnixMilliseconds() {
		return audit.Event{}, ErrInvalidPublicationHeadGate
	}
	claimEvent, found, err := findModelAuditEvent(ctx, ledger, scope, audit.EventPublicationClaimed, authorization.Identity())
	if err != nil {
		return audit.Event{}, err
	}
	if !found || claimEvent.Identity() != claim.EventIdentity() {
		return audit.Event{}, ErrInvalidPublicationClaim
	}
	parents := []string{authorization.Identity(), claim.Identity(), attempt.Identity(), headEvent.Identity(), result.HeadReconciliationIdentity()}
	if result.Status() == PublicationSucceeded {
		parents = append(parents, result.ExternalReferenceIdentity())
	}
	sort.Strings(parents)
	for range maxModelPipelineAuditConflicts {
		before, hadBefore, err := ledger.Head(ctx, scope)
		if err != nil {
			return audit.Event{}, err
		}
		existing, same, conflict, err := inspectPublicationCompletions(ctx, ledger, scope, attempt.Identity(), result.Identity())
		if err != nil {
			return audit.Event{}, err
		}
		if same {
			if !slices.Equal(existing.CausalParentIdentities(), parents) {
				return audit.Event{}, ErrPublicationCompletionConflict
			}
			return existing, nil
		}
		if conflict {
			return audit.Event{}, ErrPublicationCompletionConflict
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
		event, err := audit.NewEvent(scope, sequence, previous, audit.EventPublicationCompleted, result.Identity(), parents, occurredAt)
		if err != nil {
			return audit.Event{}, err
		}
		if err := ledger.Append(ctx, previous, event); err == nil {
			return event, nil
		} else if !errors.Is(err, audit.ErrAuditHeadConflict) {
			return audit.Event{}, err
		}
	}
	return audit.Event{}, ErrPublicationCompletionConflict
}

func inspectPublicationCompletions(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, attemptIdentity, resultIdentity string) (audit.Event, bool, bool, error) {
	var after uint64
	for {
		events, err := ledger.Read(ctx, scope, after, 1_000)
		if err != nil {
			return audit.Event{}, false, false, err
		}
		for _, event := range events {
			if event.Kind() != audit.EventPublicationCompleted {
				continue
			}
			if event.SubjectIdentity() == resultIdentity {
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

func (c PublicationClaim) Identity() string                   { return c.identity }
func (c PublicationClaim) EventIdentity() string              { return c.event.Identity() }
func (c PublicationClaim) ReviewScopeIdentity() string        { return c.event.Scope().Identity() }
func (c PublicationClaim) AuthorizationIdentity() string      { return c.authorizationIdentity }
func (c PublicationClaim) PlanIdentity() string               { return c.planIdentity }
func (c PublicationClaim) TargetIdentity() string             { return c.targetIdentity }
func (c PublicationClaim) IdempotencyKey() string             { return c.idempotencyKey }
func (c PublicationClaim) AuthorizationEventIdentity() string { return c.authorizationEventIdentity }
func (c PublicationClaim) String() string                     { return "publication claim" }
func (c PublicationClaim) GoString() string                   { return "review.PublicationClaim{<redacted>}" }
func (c PublicationClaim) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication claim", "review.PublicationClaim{<redacted>}")
}

// Validate verifies the exact audit event and authorization, plan, target, and idempotency references.
func (c PublicationClaim) Validate() error {
	if err := c.event.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPublicationClaim, err)
	}
	for _, identity := range []string{c.authorizationIdentity, c.planIdentity, c.targetIdentity, c.idempotencyKey, c.authorizationEventIdentity} {
		if !validCandidateDigest(identity) {
			return ErrInvalidPublicationClaim
		}
	}
	if c.event.Kind() != audit.EventPublicationClaimed || c.event.SubjectIdentity() != c.authorizationIdentity || !slices.Equal(c.event.CausalParentIdentities(), publicationClaimIdentityParents(c)) {
		return ErrInvalidPublicationClaim
	}
	if c.identity != derivePublicationClaimIdentity(c) {
		return ErrInvalidPublicationClaimIdentity
	}
	return nil
}

func publicationClaimIdentityParents(claim PublicationClaim) []string {
	parents := []string{claim.authorizationIdentity, claim.planIdentity, claim.targetIdentity, claim.idempotencyKey, claim.authorizationEventIdentity}
	sort.Strings(parents)
	return parents
}

func derivePublicationClaimIdentity(claim PublicationClaim) string {
	preimage := struct {
		Contract           string `json:"contract"`
		Version            int    `json:"version"`
		Event              string `json:"event"`
		Authorization      string `json:"authorization"`
		Plan               string `json:"plan"`
		Target             string `json:"target"`
		Idempotency        string `json:"idempotency"`
		AuthorizationEvent string `json:"authorization_event"`
	}{
		Contract: "open-trestle/publication-claim", Version: 1,
		Event: claim.event.Identity(), Authorization: claim.authorizationIdentity,
		Plan: claim.planIdentity, Target: claim.targetIdentity, Idempotency: claim.idempotencyKey,
		AuthorizationEvent: claim.authorizationEventIdentity,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
