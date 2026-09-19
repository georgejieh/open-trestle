package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/georgejieh/open-trestle/internal/policy"
)

var (
	// ErrPublicationPlanNotReady identifies blocked or empty readiness that cannot form an external-write proposal.
	ErrPublicationPlanNotReady = errors.New("publication plan is not ready")
	// ErrInvalidSourceSnapshotBinding identifies a malformed reviewed-head evidence binding.
	ErrInvalidSourceSnapshotBinding = errors.New("invalid source snapshot binding")
	// ErrInvalidPublicationPlan identifies inconsistent target, finding, or readiness fields.
	ErrInvalidPublicationPlan = errors.New("invalid publication plan")
	// ErrInvalidPublicationPlanIdentity identifies plan content inconsistent with its identity.
	ErrInvalidPublicationPlanIdentity = errors.New("invalid publication plan identity")
	// ErrPublicationNotAuthorized identifies a denied, expired, wrong-capability, or wrong-scope effect decision.
	ErrPublicationNotAuthorized = errors.New("publication not authorized")
	// ErrInvalidPublicationAuthorization identifies inconsistent publication authorization fields.
	ErrInvalidPublicationAuthorization = errors.New("invalid publication authorization")
	// ErrInvalidPublicationAuthorizationIdentity identifies authorization content inconsistent with its identity.
	ErrInvalidPublicationAuthorizationIdentity = errors.New("invalid publication authorization identity")
)

// PublicationPlan binds advisory readiness to one exact immutable source-control target.
type PublicationPlan struct {
	identity                       string
	reviewScopeIdentity            string
	readinessIdentity              string
	generationContextIdentity      string
	snapshotIdentity               string
	target                         PublicationTarget
	sourceSnapshotBindingIdentity  string
	hasAcquiredSource              bool
	sourceRepositoryIdentity       string
	sourceHeadRevisionIdentity     string
	acquiredContextBindingIdentity string
	inlineFindings                 []VerifiedFinding
	summaryOnlyFindings            []VerifiedFinding
}

func newPublicationPlan(readiness PublicationReadiness, target PublicationTarget, sourceSnapshotBindingIdentity string) (PublicationPlan, error) {
	if err := readiness.Validate(); err != nil {
		return PublicationPlan{}, err
	}
	if readiness.Status() != PublicationAdvisoryReady {
		return PublicationPlan{}, ErrPublicationPlanNotReady
	}
	if err := target.Validate(); err != nil {
		return PublicationPlan{}, err
	}
	if !validCandidateDigest(sourceSnapshotBindingIdentity) {
		return PublicationPlan{}, ErrInvalidSourceSnapshotBinding
	}
	plan := PublicationPlan{
		reviewScopeIdentity: readiness.ReviewScopeIdentity(), readinessIdentity: readiness.Identity(),
		generationContextIdentity: readiness.GenerationContextIdentity(), snapshotIdentity: readiness.snapshotIdentity,
		target: target, sourceSnapshotBindingIdentity: sourceSnapshotBindingIdentity,
		inlineFindings: readiness.InlineFindings(), summaryOnlyFindings: readiness.SummaryOnlyFindings(),
	}
	plan.identity = derivePublicationPlanIdentity(plan)
	if err := plan.Validate(); err != nil {
		return PublicationPlan{}, err
	}
	return plan, nil
}

// NewPublicationPlan creates an external-write proposal bound to verified acquired source and context.
func NewPublicationPlan(readiness PublicationReadiness, target PublicationTarget, source AcquiredReviewSnapshot, contextBinding AcquiredContextBinding) (PublicationPlan, error) {
	if err := source.Validate(); err != nil {
		return PublicationPlan{}, err
	}
	if err := contextBinding.Validate(); err != nil {
		return PublicationPlan{}, err
	}
	matchingSnapshot := source.PipelineSnapshotIdentity() == readiness.snapshotIdentity
	matchingContextSource := contextBinding.AcquiredSnapshotIdentity() == source.Identity()
	matchingContextPipeline := contextBinding.PipelineSnapshotIdentity() == source.PipelineSnapshotIdentity()
	matchingGenerationContext := contextBinding.ContextPacketIdentity() == readiness.GenerationContextIdentity()
	matchingScope := contextBinding.ReviewScopeIdentity() == readiness.ReviewScopeIdentity()
	if !matchingSnapshot || !matchingContextSource || !matchingContextPipeline || !matchingGenerationContext || !matchingScope || !source.MatchesPublicationTarget(target) {
		return PublicationPlan{}, ErrInvalidSourceSnapshotBinding
	}
	plan, err := newPublicationPlan(readiness, target, source.Identity())
	if err != nil {
		return PublicationPlan{}, err
	}
	plan.hasAcquiredSource = true
	plan.sourceRepositoryIdentity = source.RepositoryIdentity()
	plan.sourceHeadRevisionIdentity = source.HeadRevision().Identity()
	plan.acquiredContextBindingIdentity = contextBinding.Identity()
	plan.identity = derivePublicationPlanIdentity(plan)
	if err := plan.Validate(); err != nil {
		return PublicationPlan{}, err
	}
	return plan, nil
}

func (p PublicationPlan) Identity() string                  { return p.identity }
func (p PublicationPlan) ReviewScopeIdentity() string       { return p.reviewScopeIdentity }
func (p PublicationPlan) ReadinessIdentity() string         { return p.readinessIdentity }
func (p PublicationPlan) GenerationContextIdentity() string { return p.generationContextIdentity }
func (p PublicationPlan) Target() PublicationTarget         { return p.target }
func (p PublicationPlan) SourceSnapshotBindingIdentity() string {
	return p.sourceSnapshotBindingIdentity
}
func (p PublicationPlan) HasAcquiredSource() bool            { return p.hasAcquiredSource }
func (p PublicationPlan) SourceRepositoryIdentity() string   { return p.sourceRepositoryIdentity }
func (p PublicationPlan) SourceHeadRevisionIdentity() string { return p.sourceHeadRevisionIdentity }
func (p PublicationPlan) AcquiredContextBindingIdentity() string {
	return p.acquiredContextBindingIdentity
}
func (p PublicationPlan) InlineFindingCount() int      { return len(p.inlineFindings) }
func (p PublicationPlan) SummaryOnlyFindingCount() int { return len(p.summaryOnlyFindings) }
func (p PublicationPlan) InlineFindings() []VerifiedFinding {
	return append([]VerifiedFinding(nil), p.inlineFindings...)
}
func (p PublicationPlan) SummaryOnlyFindings() []VerifiedFinding {
	return append([]VerifiedFinding(nil), p.summaryOnlyFindings...)
}

// AuthorizesPublication always returns false because a plan is not an effect grant.
func (p PublicationPlan) AuthorizesPublication() bool { return false }
func (p PublicationPlan) String() string              { return "publication plan" }
func (p PublicationPlan) GoString() string            { return "review.PublicationPlan{<redacted>}" }
func (p PublicationPlan) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication plan", "review.PublicationPlan{<redacted>}")
}

// Validate verifies target, finding sets, scope, snapshot binding, and content identity.
func (p PublicationPlan) Validate() error {
	identities := []string{
		p.reviewScopeIdentity, p.readinessIdentity, p.generationContextIdentity,
		p.snapshotIdentity, p.sourceSnapshotBindingIdentity,
	}
	for _, identity := range identities {
		if !validCandidateDigest(identity) {
			return ErrInvalidPublicationPlan
		}
	}
	if err := p.target.Validate(); err != nil {
		return err
	}
	if p.hasAcquiredSource {
		matchingRepository := p.sourceRepositoryIdentity == p.target.RepositoryIdentity().Identity()
		matchingHead := p.sourceHeadRevisionIdentity == p.target.HeadRevision().Identity()
		validRepository := validCandidateDigest(p.sourceRepositoryIdentity)
		validHead := validCandidateDigest(p.sourceHeadRevisionIdentity)
		validContext := validCandidateDigest(p.acquiredContextBindingIdentity)
		if !validRepository || !validHead || !validContext || !matchingRepository || !matchingHead {
			return ErrInvalidSourceSnapshotBinding
		}
	} else if p.sourceRepositoryIdentity != "" || p.sourceHeadRevisionIdentity != "" || p.acquiredContextBindingIdentity != "" {
		return ErrInvalidSourceSnapshotBinding
	}
	totalFindings := len(p.inlineFindings) + len(p.summaryOnlyFindings)
	if totalFindings == 0 || len(p.inlineFindings) > int(maxPublicationInlineFindings) || totalFindings > maxCandidateFindings {
		return ErrInvalidPublicationPlan
	}
	seen := make(map[string]struct{}, len(p.inlineFindings)+len(p.summaryOnlyFindings))
	groups := [][]VerifiedFinding{p.inlineFindings, p.summaryOnlyFindings}
	for _, findings := range groups {
		for index, finding := range findings {
			if err := finding.Validate(); err != nil {
				return err
			}
			if finding.snapshotIdentity != p.snapshotIdentity || index > 0 && publicationFindingLess(finding, findings[index-1]) {
				return ErrInvalidPublicationPlan
			}
			if _, exists := seen[finding.Identity()]; exists {
				return ErrInvalidPublicationPlan
			}
			seen[finding.Identity()] = struct{}{}
		}
	}
	if len(p.inlineFindings) != 0 && len(p.summaryOnlyFindings) != 0 && publicationFindingLess(p.summaryOnlyFindings[0], p.inlineFindings[len(p.inlineFindings)-1]) {
		return ErrInvalidPublicationPlan
	}
	if p.identity != derivePublicationPlanIdentity(p) {
		return ErrInvalidPublicationPlanIdentity
	}
	return nil
}

// PublicationAuthorization is an expiring exact-target external-write grant.
type PublicationAuthorization struct {
	identity       string
	plan           PublicationPlan
	effect         policy.EffectAuthorization
	idempotencyKey string
}

// NewPublicationAuthorization grants dispatch only when a live publication effect decision matches the plan scope.
func NewPublicationAuthorization(plan PublicationPlan, effect policy.EffectAuthorization, at time.Time) (PublicationAuthorization, error) {
	if err := plan.Validate(); err != nil {
		return PublicationAuthorization{}, err
	}
	if err := effect.Validate(); err != nil {
		return PublicationAuthorization{}, err
	}
	if !plan.hasAcquiredSource {
		return PublicationAuthorization{}, ErrInvalidSourceSnapshotBinding
	}
	if !effect.Allows(policy.CapabilityPublication, plan.ReviewScopeIdentity(), at) {
		return PublicationAuthorization{}, ErrPublicationNotAuthorized
	}
	authorization := PublicationAuthorization{plan: plan, effect: effect, idempotencyKey: derivePublicationIdempotencyKey(plan)}
	authorization.identity = derivePublicationAuthorizationIdentity(authorization)
	if err := authorization.Validate(); err != nil {
		return PublicationAuthorization{}, err
	}
	return authorization, nil
}

func (a PublicationAuthorization) Identity() string                                { return a.identity }
func (a PublicationAuthorization) PlanIdentity() string                            { return a.plan.Identity() }
func (a PublicationAuthorization) TargetIdentity() string                          { return a.plan.Target().Identity() }
func (a PublicationAuthorization) EffectAuthorizationIdentity() string             { return a.effect.Identity() }
func (a PublicationAuthorization) IdempotencyKey() string                          { return a.idempotencyKey }
func (a PublicationAuthorization) Plan() PublicationPlan                           { return a.plan }
func (a PublicationAuthorization) EffectAuthorization() policy.EffectAuthorization { return a.effect }
func (a PublicationAuthorization) String() string                                  { return "publication authorization" }
func (a PublicationAuthorization) GoString() string {
	return "review.PublicationAuthorization{<redacted>}"
}
func (a PublicationAuthorization) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication authorization", "review.PublicationAuthorization{<redacted>}")
}

// Authorizes reports whether the grant permits the exact target at the supplied time.
func (a PublicationAuthorization) Authorizes(target PublicationTarget, at time.Time) bool {
	return a.Validate() == nil && target.Validate() == nil && target.Identity() == a.TargetIdentity() && a.effect.Allows(policy.CapabilityPublication, a.plan.ReviewScopeIdentity(), at)
}

// Validate verifies the plan, effect, deterministic idempotency key, and content identity.
func (a PublicationAuthorization) Validate() error {
	if err := a.plan.Validate(); err != nil {
		return err
	}
	if err := a.effect.Validate(); err != nil {
		return err
	}
	if !a.plan.hasAcquiredSource {
		return ErrInvalidPublicationAuthorization
	}
	matchingCapability := a.effect.Capability() == policy.CapabilityPublication
	matchingOutcome := a.effect.Outcome() == policy.DecisionAllow
	matchingScope := a.effect.ScopeIdentity() == a.plan.ReviewScopeIdentity()
	matchingKey := a.idempotencyKey == derivePublicationIdempotencyKey(a.plan)
	if !matchingCapability || !matchingOutcome || !matchingScope || !matchingKey {
		return ErrInvalidPublicationAuthorization
	}
	if a.identity != derivePublicationAuthorizationIdentity(a) {
		return ErrInvalidPublicationAuthorizationIdentity
	}
	return nil
}

func derivePublicationIdempotencyKey(plan PublicationPlan) string {
	preimage := "open-trestle/publication-idempotency/v1/" + plan.Identity()
	digest := sha256.Sum256([]byte(preimage))
	return hex.EncodeToString(digest[:])
}

func derivePublicationPlanIdentity(plan PublicationPlan) string {
	inline := verifiedFindingIdentities(plan.inlineFindings)
	summary := verifiedFindingIdentities(plan.summaryOnlyFindings)
	preimage := struct {
		Contract          string   `json:"contract"`
		Version           int      `json:"version"`
		Scope             string   `json:"scope"`
		Readiness         string   `json:"readiness"`
		GenerationContext string   `json:"generation_context"`
		Snapshot          string   `json:"snapshot"`
		Target            string   `json:"target"`
		SourceBinding     string   `json:"source_binding"`
		Acquired          bool     `json:"acquired"`
		Repository        string   `json:"repository"`
		HeadRevision      string   `json:"head_revision"`
		AcquiredContext   string   `json:"acquired_context"`
		Inline            []string `json:"inline"`
		Summary           []string `json:"summary"`
	}{
		Contract: "open-trestle/publication-plan", Version: 1,
		Scope: plan.reviewScopeIdentity, Readiness: plan.readinessIdentity,
		GenerationContext: plan.generationContextIdentity, Snapshot: plan.snapshotIdentity, Target: plan.target.Identity(), SourceBinding: plan.sourceSnapshotBindingIdentity,
		Acquired: plan.hasAcquiredSource, Repository: plan.sourceRepositoryIdentity,
		HeadRevision: plan.sourceHeadRevisionIdentity, AcquiredContext: plan.acquiredContextBindingIdentity, Inline: inline, Summary: summary,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func verifiedFindingIdentities(findings []VerifiedFinding) []string {
	identities := make([]string, len(findings))
	for index, finding := range findings {
		identities[index] = finding.Identity()
	}
	return identities
}

func derivePublicationAuthorizationIdentity(authorization PublicationAuthorization) string {
	preimage := struct {
		Contract       string `json:"contract"`
		Version        int    `json:"version"`
		Plan           string `json:"plan"`
		Effect         string `json:"effect"`
		IdempotencyKey string `json:"idempotency_key"`
	}{
		Contract: "open-trestle/publication-authorization", Version: 1,
		Plan: authorization.plan.Identity(), Effect: authorization.effect.Identity(),
		IdempotencyKey: authorization.idempotencyKey,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
