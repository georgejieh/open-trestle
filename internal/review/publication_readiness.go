package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/georgejieh/open-trestle/internal/gateway"
)

const maxPublicationInlineFindings uint8 = 50

var (
	// ErrInvalidPublicationSeverity identifies an unknown minimum advisory severity.
	ErrInvalidPublicationSeverity = errors.New("invalid publication severity")
	// ErrInvalidPublicationLimit identifies an excessive inline finding limit.
	ErrInvalidPublicationLimit = errors.New("invalid publication limit")
	// ErrInvalidPublicationPolicyIdentity identifies policy content inconsistent with its identity.
	ErrInvalidPublicationPolicyIdentity = errors.New("invalid publication policy identity")
	// ErrInvalidPublicationReadinessStatus identifies an unknown readiness outcome.
	ErrInvalidPublicationReadinessStatus = errors.New("invalid publication readiness status")
	// ErrPublicationReadinessBindingMismatch identifies an unrelated finding set and verification receipt.
	ErrPublicationReadinessBindingMismatch = errors.New("publication readiness binding mismatch")
	// ErrInvalidPublicationReadiness identifies inconsistent counts, ordering, or selection.
	ErrInvalidPublicationReadiness = errors.New("invalid publication readiness")
	// ErrInvalidPublicationReadinessIdentity identifies readiness content inconsistent with its identity.
	ErrInvalidPublicationReadinessIdentity = errors.New("invalid publication readiness identity")
)

// PublicationPolicy controls advisory eligibility without authorizing an external write.
type PublicationPolicy struct {
	identity            string
	minimumSeverity     Severity
	maxInlineFindings   uint8
	minimumIndependence gateway.RouteIndependenceLevel
	blockOnInconclusive bool
}

func NewPublicationPolicy(minimumSeverity Severity, maxInlineFindings uint8, minimumIndependence gateway.RouteIndependenceLevel, blockOnInconclusive bool) (PublicationPolicy, error) {
	if !isKnownSeverity(minimumSeverity) {
		return PublicationPolicy{}, ErrInvalidPublicationSeverity
	}
	if maxInlineFindings > maxPublicationInlineFindings {
		return PublicationPolicy{}, ErrInvalidPublicationLimit
	}
	if err := minimumIndependence.Validate(); err != nil {
		return PublicationPolicy{}, err
	}
	policy := PublicationPolicy{
		minimumSeverity: minimumSeverity, maxInlineFindings: maxInlineFindings,
		minimumIndependence: minimumIndependence, blockOnInconclusive: blockOnInconclusive,
	}
	policy.identity = derivePublicationPolicyIdentity(policy)
	return policy, nil
}

func (p PublicationPolicy) Identity() string          { return p.identity }
func (p PublicationPolicy) MinimumSeverity() Severity { return p.minimumSeverity }
func (p PublicationPolicy) MaxInlineFindings() uint8  { return p.maxInlineFindings }
func (p PublicationPolicy) MinimumIndependence() gateway.RouteIndependenceLevel {
	return p.minimumIndependence
}
func (p PublicationPolicy) BlocksOnInconclusive() bool { return p.blockOnInconclusive }
func (p PublicationPolicy) String() string             { return "publication policy" }
func (p PublicationPolicy) GoString() string           { return "review.PublicationPolicy{<redacted>}" }
func (p PublicationPolicy) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication policy", "review.PublicationPolicy{<redacted>}")
}
func (p PublicationPolicy) Validate() error {
	if !isKnownSeverity(p.minimumSeverity) {
		return ErrInvalidPublicationSeverity
	}
	if p.maxInlineFindings > maxPublicationInlineFindings {
		return ErrInvalidPublicationLimit
	}
	if err := p.minimumIndependence.Validate(); err != nil {
		return err
	}
	if p.identity != derivePublicationPolicyIdentity(p) {
		return ErrInvalidPublicationPolicyIdentity
	}
	return nil
}

// PublicationReadinessStatus identifies a truthful advisory-selection outcome.
type PublicationReadinessStatus uint8

const (
	PublicationAdvisoryReady PublicationReadinessStatus = iota + 1
	PublicationNoVerifiedFindings
	PublicationBelowThreshold
	PublicationBlockedInconclusive
	PublicationBlockedIndependence
)

func (s PublicationReadinessStatus) String() string {
	switch s {
	case PublicationAdvisoryReady:
		return "advisory_ready"
	case PublicationNoVerifiedFindings:
		return "no_verified_findings"
	case PublicationBelowThreshold:
		return "below_threshold"
	case PublicationBlockedInconclusive:
		return "blocked_inconclusive"
	case PublicationBlockedIndependence:
		return "blocked_independence"
	default:
		return ""
	}
}
func ParsePublicationReadinessStatus(value string) (PublicationReadinessStatus, error) {
	for status := PublicationAdvisoryReady; status <= PublicationBlockedIndependence; status++ {
		if status.String() == value {
			return status, nil
		}
	}
	return 0, ErrInvalidPublicationReadinessStatus
}
func (s PublicationReadinessStatus) Validate() error {
	if s.String() == "" {
		return ErrInvalidPublicationReadinessStatus
	}
	return nil
}

// PublicationReadiness selects advisory output but never grants an external effect.
type PublicationReadiness struct {
	identity                    string
	status                      PublicationReadinessStatus
	policy                      PublicationPolicy
	verificationReceiptIdentity string
	verifiedFindingSetIdentity  string
	reviewScopeIdentity         string
	snapshotIdentity            string
	generationContextIdentity   string
	independenceLevel           gateway.RouteIndependenceLevel
	verifiedCount               uint8
	rejectedCount               uint8
	inconclusiveCount           uint8
	belowThresholdCount         uint8
	inlineFindings              []VerifiedFinding
	summaryOnlyFindings         []VerifiedFinding
}

func EvaluatePublicationReadiness(policy PublicationPolicy, receipt IndependentVerificationReceipt, set VerifiedFindingSet) (PublicationReadiness, error) {
	if err := policy.Validate(); err != nil {
		return PublicationReadiness{}, err
	}
	if err := receipt.Validate(); err != nil {
		return PublicationReadiness{}, err
	}
	if err := set.Validate(); err != nil {
		return PublicationReadiness{}, err
	}
	matchingIdentity := set.IndependentReceiptIdentity() == receipt.Identity() && set.SnapshotIdentity() == receipt.snapshotIdentity
	matchingCandidateCount := set.CandidateCount() == uint8(len(receipt.candidateIdentities))
	matchingVerdictCounts := set.VerifiedCount() == receipt.VerifiedCount() && set.RejectedCount() == receipt.RejectedCount() && set.InconclusiveCount() == receipt.InconclusiveCount()
	matchingCounts := matchingCandidateCount && matchingVerdictCounts
	if !matchingIdentity || !matchingCounts {
		return PublicationReadiness{}, ErrPublicationReadinessBindingMismatch
	}
	r := PublicationReadiness{
		policy: policy, verificationReceiptIdentity: receipt.Identity(),
		verifiedFindingSetIdentity: set.Identity(), reviewScopeIdentity: receipt.ReviewScopeIdentity(),
		snapshotIdentity: set.SnapshotIdentity(), generationContextIdentity: receipt.GenerationContextIdentity(),
		independenceLevel: receipt.IndependenceLevel(), verifiedCount: set.VerifiedCount(),
		rejectedCount: set.RejectedCount(), inconclusiveCount: set.InconclusiveCount(),
	}
	switch {
	case receipt.IndependenceLevel() < policy.MinimumIndependence():
		r.status = PublicationBlockedIndependence
	case policy.BlocksOnInconclusive() && set.InconclusiveCount() != 0:
		r.status = PublicationBlockedInconclusive
	case set.VerifiedCount() == 0:
		r.status = PublicationNoVerifiedFindings
	default:
		eligible := make([]VerifiedFinding, 0, len(set.findings))
		for _, finding := range set.findings {
			if severityRank(finding.Severity()) < severityRank(policy.MinimumSeverity()) {
				r.belowThresholdCount++
				continue
			}
			eligible = append(eligible, finding)
		}
		if len(eligible) == 0 {
			r.status = PublicationBelowThreshold
			break
		}
		sort.Slice(eligible, func(i, j int) bool { return publicationFindingLess(eligible[i], eligible[j]) })
		count := min(len(eligible), int(policy.MaxInlineFindings()))
		r.inlineFindings = append([]VerifiedFinding(nil), eligible[:count]...)
		for _, finding := range eligible[count:] {
			r.summaryOnlyFindings = append(r.summaryOnlyFindings, finding)
		}
		if len(r.inlineFindings) == 0 {
			r.inlineFindings = nil
		}
		if len(r.summaryOnlyFindings) == 0 {
			r.summaryOnlyFindings = nil
		}
		r.status = PublicationAdvisoryReady
	}
	r.identity = derivePublicationReadinessIdentity(r)
	if err := r.Validate(); err != nil {
		return PublicationReadiness{}, err
	}
	return r, nil
}

func (r PublicationReadiness) Identity() string                   { return r.identity }
func (r PublicationReadiness) Status() PublicationReadinessStatus { return r.status }
func (r PublicationReadiness) PolicyIdentity() string             { return r.policy.Identity() }
func (r PublicationReadiness) Policy() PublicationPolicy          { return r.policy }
func (r PublicationReadiness) VerificationReceiptIdentity() string {
	return r.verificationReceiptIdentity
}
func (r PublicationReadiness) VerifiedFindingSetIdentity() string {
	return r.verifiedFindingSetIdentity
}
func (r PublicationReadiness) ReviewScopeIdentity() string       { return r.reviewScopeIdentity }
func (r PublicationReadiness) GenerationContextIdentity() string { return r.generationContextIdentity }
func (r PublicationReadiness) VerifiedCount() uint8              { return r.verifiedCount }
func (r PublicationReadiness) RejectedCount() uint8              { return r.rejectedCount }
func (r PublicationReadiness) InconclusiveCount() uint8          { return r.inconclusiveCount }
func (r PublicationReadiness) BelowThresholdCount() uint8        { return r.belowThresholdCount }
func (r PublicationReadiness) SummaryOnlyCount() int             { return len(r.summaryOnlyFindings) }
func (r PublicationReadiness) SummaryOnlyFindings() []VerifiedFinding {
	return append([]VerifiedFinding(nil), r.summaryOnlyFindings...)
}
func (r PublicationReadiness) InlineFindings() []VerifiedFinding {
	return append([]VerifiedFinding(nil), r.inlineFindings...)
}
func (r PublicationReadiness) AuthorizesPublication() bool { return false }
func (r PublicationReadiness) String() string              { return "publication readiness" }
func (r PublicationReadiness) GoString() string            { return "review.PublicationReadiness{<redacted>}" }
func (r PublicationReadiness) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication readiness", "review.PublicationReadiness{<redacted>}")
}

func (r PublicationReadiness) Validate() error {
	if err := r.status.Validate(); err != nil {
		return err
	}
	if err := r.policy.Validate(); err != nil {
		return err
	}
	for _, id := range []string{r.verificationReceiptIdentity, r.verifiedFindingSetIdentity, r.reviewScopeIdentity, r.snapshotIdentity, r.generationContextIdentity} {
		if !validCandidateDigest(id) {
			return ErrInvalidPublicationReadiness
		}
	}
	if err := r.independenceLevel.Validate(); err != nil {
		return err
	}
	totalResults := int(r.verifiedCount) + int(r.rejectedCount) + int(r.inconclusiveCount)
	accountedVerified := len(r.inlineFindings) + len(r.summaryOnlyFindings) + int(r.belowThresholdCount)
	if totalResults > maxCandidateFindings || r.belowThresholdCount > r.verifiedCount || len(r.inlineFindings) > int(r.policy.MaxInlineFindings()) || accountedVerified > int(r.verifiedCount) {
		return ErrInvalidPublicationReadiness
	}
	if err := r.validateSelections(); err != nil {
		return err
	}
	if r.identity != derivePublicationReadinessIdentity(r) {
		return ErrInvalidPublicationReadinessIdentity
	}
	return nil
}
func (r PublicationReadiness) validateSelections() error {
	has := len(r.inlineFindings) != 0 || len(r.summaryOnlyFindings) != 0 || r.belowThresholdCount != 0
	switch r.status {
	case PublicationBlockedIndependence:
		if r.independenceLevel >= r.policy.MinimumIndependence() || has {
			return ErrInvalidPublicationReadiness
		}
	case PublicationBlockedInconclusive:
		if !r.policy.BlocksOnInconclusive() || r.inconclusiveCount == 0 || r.independenceLevel < r.policy.MinimumIndependence() || has {
			return ErrInvalidPublicationReadiness
		}
	case PublicationNoVerifiedFindings:
		if r.verifiedCount != 0 || has {
			return ErrInvalidPublicationReadiness
		}
	case PublicationBelowThreshold:
		if r.verifiedCount == 0 || r.belowThresholdCount != r.verifiedCount || len(r.inlineFindings) != 0 || len(r.summaryOnlyFindings) != 0 {
			return ErrInvalidPublicationReadiness
		}
	case PublicationAdvisoryReady:
		if len(r.inlineFindings)+len(r.summaryOnlyFindings) == 0 || len(r.inlineFindings)+len(r.summaryOnlyFindings)+int(r.belowThresholdCount) != int(r.verifiedCount) {
			return ErrInvalidPublicationReadiness
		}
	}
	seen := make(map[string]struct{}, len(r.inlineFindings)+len(r.summaryOnlyFindings))
	for index, finding := range r.inlineFindings {
		if err := finding.Validate(); err != nil {
			return err
		}
		wrongSnapshot := finding.snapshotIdentity != r.snapshotIdentity
		belowThreshold := severityRank(finding.Severity()) < severityRank(r.policy.MinimumSeverity())
		outOfOrder := index > 0 && publicationFindingLess(finding, r.inlineFindings[index-1])
		if wrongSnapshot || belowThreshold || outOfOrder {
			return ErrInvalidPublicationReadiness
		}
		seen[finding.Identity()] = struct{}{}
	}
	if len(r.inlineFindings) != 0 && len(r.summaryOnlyFindings) != 0 && publicationFindingLess(r.summaryOnlyFindings[0], r.inlineFindings[len(r.inlineFindings)-1]) {
		return ErrInvalidPublicationReadiness
	}
	for index, finding := range r.summaryOnlyFindings {
		if err := finding.Validate(); err != nil {
			return err
		}
		wrongSnapshot := finding.snapshotIdentity != r.snapshotIdentity
		belowThreshold := severityRank(finding.Severity()) < severityRank(r.policy.MinimumSeverity())
		outOfOrder := index > 0 && publicationFindingLess(finding, r.summaryOnlyFindings[index-1])
		if wrongSnapshot || belowThreshold || outOfOrder {
			return ErrInvalidPublicationReadiness
		}
		if _, exists := seen[finding.Identity()]; exists {
			return ErrInvalidPublicationReadiness
		}
		seen[finding.Identity()] = struct{}{}
	}
	return nil
}
func severityRank(s Severity) uint8 {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	}
	return 0
}
func publicationFindingLess(a, b VerifiedFinding) bool {
	if severityRank(a.Severity()) != severityRank(b.Severity()) {
		return severityRank(a.Severity()) > severityRank(b.Severity())
	}
	if a.SourceRange().Path() != b.SourceRange().Path() {
		return a.SourceRange().Path() < b.SourceRange().Path()
	}
	if a.SourceRange().StartLine() != b.SourceRange().StartLine() {
		return a.SourceRange().StartLine() < b.SourceRange().StartLine()
	}
	if a.SourceRange().EndLine() != b.SourceRange().EndLine() {
		return a.SourceRange().EndLine() < b.SourceRange().EndLine()
	}
	return a.Fingerprint() < b.Fingerprint()
}
func derivePublicationPolicyIdentity(p PublicationPolicy) string {
	v := struct {
		Contract     string `json:"contract"`
		Version      int    `json:"version"`
		Severity     string `json:"severity"`
		Max          uint8  `json:"max"`
		Independence string `json:"independence"`
		Block        bool   `json:"block"`
	}{
		Contract: "open-trestle/publication-policy", Version: 1,
		Severity: string(p.minimumSeverity), Max: p.maxInlineFindings,
		Independence: p.minimumIndependence.String(), Block: p.blockOnInconclusive,
	}
	b, _ := json.Marshal(v)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
func derivePublicationReadinessIdentity(r PublicationReadiness) string {
	inline := make([]string, len(r.inlineFindings))
	for i, f := range r.inlineFindings {
		inline[i] = f.Identity()
	}
	summary := make([]string, len(r.summaryOnlyFindings))
	for i, f := range r.summaryOnlyFindings {
		summary[i] = f.Identity()
	}
	v := struct {
		Contract          string   `json:"contract"`
		Version           int      `json:"version"`
		Status            string   `json:"status"`
		Policy            string   `json:"policy"`
		Receipt           string   `json:"receipt"`
		Set               string   `json:"set"`
		Scope             string   `json:"scope"`
		Snapshot          string   `json:"snapshot"`
		GenerationContext string   `json:"generation_context"`
		Independence      string   `json:"independence"`
		Verified          uint8    `json:"verified"`
		Rejected          uint8    `json:"rejected"`
		Inconclusive      uint8    `json:"inconclusive"`
		Below             uint8    `json:"below"`
		Inline            []string `json:"inline"`
		Summary           []string `json:"summary"`
	}{
		Contract: "open-trestle/publication-readiness", Version: 1,
		Status: r.status.String(), Policy: r.policy.Identity(), Receipt: r.verificationReceiptIdentity,
		Set: r.verifiedFindingSetIdentity, Scope: r.reviewScopeIdentity, Snapshot: r.snapshotIdentity, GenerationContext: r.generationContextIdentity,
		Independence: r.independenceLevel.String(), Verified: r.verifiedCount,
		Rejected: r.rejectedCount, Inconclusive: r.inconclusiveCount, Below: r.belowThresholdCount,
		Inline: inline, Summary: summary,
	}
	b, _ := json.Marshal(v)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}
