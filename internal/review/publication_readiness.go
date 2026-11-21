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
	// ErrInvalidPublicationSelection identifies malformed or cross-wired selected findings.
	ErrInvalidPublicationSelection = errors.New("invalid publication selection")
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
	PublicationBlockedSensitiveContent
	PublicationBlockedInstructionRisk
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
	case PublicationBlockedSensitiveContent:
		return "blocked_sensitive_content"
	case PublicationBlockedInstructionRisk:
		return "blocked_instruction_risk"
	default:
		return ""
	}
}
func ParsePublicationReadinessStatus(value string) (PublicationReadinessStatus, error) {
	for status := PublicationAdvisoryReady; status <= PublicationBlockedInstructionRisk; status++ {
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

// PublicationSelection is the frozen policy-selected projection scanned and rendered for publication.
type PublicationSelection struct {
	identity                    string
	status                      PublicationReadinessStatus
	policy                      PublicationPolicy
	verificationReceiptIdentity string
	verifiedFindingSetIdentity  string
	reviewScopeIdentity         string
	snapshotIdentity            string
	independenceLevel           gateway.RouteIndependenceLevel
	verifiedCount               uint8
	rejectedCount               uint8
	inconclusiveCount           uint8
	belowThresholdCount         uint8
	inlineFindings              []VerifiedFinding
	summaryOnlyFindings         []VerifiedFinding
	inlineProjection            []PublishableFinding
	summaryOnlyProjection       []PublishableFinding
}

func SelectPublicationFindings(policy PublicationPolicy, receipt IndependentVerificationReceipt, set VerifiedFindingSet) (PublicationSelection, error) {
	if policy.Validate() != nil || receipt.Validate() != nil || set.Validate() != nil {
		return PublicationSelection{}, ErrInvalidPublicationSelection
	}
	matchingIdentity := set.IndependentReceiptIdentity() == receipt.Identity() && set.SnapshotIdentity() == receipt.SnapshotIdentity()
	matchingCounts := set.CandidateCount() == uint8(len(receipt.candidateIdentities)) && set.VerifiedCount() == receipt.VerifiedCount() && set.RejectedCount() == receipt.RejectedCount() && set.InconclusiveCount() == receipt.InconclusiveCount()
	if !matchingIdentity || !matchingCounts {
		return PublicationSelection{}, ErrPublicationReadinessBindingMismatch
	}
	selection := PublicationSelection{
		policy: policy, verificationReceiptIdentity: receipt.Identity(), verifiedFindingSetIdentity: set.Identity(),
		reviewScopeIdentity: receipt.ReviewScopeIdentity(), snapshotIdentity: set.SnapshotIdentity(),
		independenceLevel: receipt.IndependenceLevel(), verifiedCount: set.VerifiedCount(), rejectedCount: set.RejectedCount(), inconclusiveCount: set.InconclusiveCount(),
	}
	eligible := make([]VerifiedFinding, 0, len(set.findings))
	for _, finding := range set.findings {
		if severityRank(finding.Severity()) < severityRank(policy.MinimumSeverity()) {
			selection.belowThresholdCount++
			continue
		}
		eligible = append(eligible, finding)
	}
	sort.Slice(eligible, func(i, j int) bool { return publicationFindingLess(eligible[i], eligible[j]) })
	// Head findings sort first. A finding on removed base lines is never
	// inline: a forge comment anchors on head lines, so it is summary-only.
	head := 0
	for head < len(eligible) && eligible[head].Side() == LineSideHead {
		head++
	}
	count := min(head, int(policy.MaxInlineFindings()))
	selection.inlineFindings = append([]VerifiedFinding(nil), eligible[:count]...)
	selection.summaryOnlyFindings = append([]VerifiedFinding(nil), eligible[count:]...)
	if len(selection.inlineFindings) == 0 {
		selection.inlineFindings = nil
	}
	if len(selection.summaryOnlyFindings) == 0 {
		selection.summaryOnlyFindings = nil
	}
	selection.inlineProjection, _ = publishableFindings(selection.inlineFindings)
	selection.summaryOnlyProjection, _ = publishableFindings(selection.summaryOnlyFindings)
	if len(selection.inlineProjection) == 0 {
		selection.inlineProjection = nil
	}
	if len(selection.summaryOnlyProjection) == 0 {
		selection.summaryOnlyProjection = nil
	}
	switch {
	case receipt.IndependenceLevel() < policy.MinimumIndependence():
		selection.status = PublicationBlockedIndependence
	case policy.BlocksOnInconclusive() && set.InconclusiveCount() != 0:
		selection.status = PublicationBlockedInconclusive
	case set.VerifiedCount() == 0:
		selection.status = PublicationNoVerifiedFindings
	case len(eligible) == 0:
		selection.status = PublicationBelowThreshold
	default:
		selection.status = PublicationAdvisoryReady
	}
	selection.identity = derivePublicationSelectionIdentity(selection)
	if selection.Validate() != nil {
		return PublicationSelection{}, ErrInvalidPublicationSelection
	}
	return selection, nil
}

func (s PublicationSelection) Identity() string                   { return s.identity }
func (s PublicationSelection) Status() PublicationReadinessStatus { return s.status }
func (s PublicationSelection) Policy() PublicationPolicy          { return s.policy }
func (s PublicationSelection) PolicyIdentity() string             { return s.policy.Identity() }
func (s PublicationSelection) VerificationReceiptIdentity() string {
	return s.verificationReceiptIdentity
}
func (s PublicationSelection) VerifiedFindingSetIdentity() string {
	return s.verifiedFindingSetIdentity
}
func (s PublicationSelection) ReviewScopeIdentity() string { return s.reviewScopeIdentity }
func (s PublicationSelection) SnapshotIdentity() string    { return s.snapshotIdentity }
func (s PublicationSelection) BelowThresholdCount() uint8  { return s.belowThresholdCount }
func (s PublicationSelection) InlineFindings() []VerifiedFinding {
	return append([]VerifiedFinding(nil), s.inlineFindings...)
}
func (s PublicationSelection) SummaryOnlyFindings() []VerifiedFinding {
	return append([]VerifiedFinding(nil), s.summaryOnlyFindings...)
}
func (s PublicationSelection) InlinePublishableFindings() []PublishableFinding {
	return append([]PublishableFinding(nil), s.inlineProjection...)
}
func (s PublicationSelection) SummaryOnlyPublishableFindings() []PublishableFinding {
	return append([]PublishableFinding(nil), s.summaryOnlyProjection...)
}
func (s PublicationSelection) PublishableCount() int {
	return len(s.inlineFindings) + len(s.summaryOnlyFindings)
}
func (s PublicationSelection) Validate() error {
	if s.status.Validate() != nil || s.status == PublicationBlockedSensitiveContent || s.status == PublicationBlockedInstructionRisk || s.policy.Validate() != nil || s.independenceLevel.Validate() != nil {
		return ErrInvalidPublicationSelection
	}
	for _, identity := range []string{s.identity, s.verificationReceiptIdentity, s.verifiedFindingSetIdentity, s.reviewScopeIdentity, s.snapshotIdentity} {
		if !validCandidateDigest(identity) {
			return ErrInvalidPublicationSelection
		}
	}
	total := int(s.verifiedCount) + int(s.rejectedCount) + int(s.inconclusiveCount)
	accounted := len(s.inlineFindings) + len(s.summaryOnlyFindings) + int(s.belowThresholdCount)
	if total > maxCandidateFindings || accounted != int(s.verifiedCount) || len(s.inlineFindings) > int(s.policy.MaxInlineFindings()) {
		return ErrInvalidPublicationSelection
	}
	hasSelected := s.PublishableCount() != 0
	switch s.status {
	case PublicationBlockedIndependence:
		if s.independenceLevel >= s.policy.MinimumIndependence() {
			return ErrInvalidPublicationSelection
		}
	case PublicationBlockedInconclusive:
		if !s.policy.BlocksOnInconclusive() || s.inconclusiveCount == 0 || s.independenceLevel < s.policy.MinimumIndependence() {
			return ErrInvalidPublicationSelection
		}
	case PublicationNoVerifiedFindings:
		if s.verifiedCount != 0 || hasSelected || s.belowThresholdCount != 0 {
			return ErrInvalidPublicationSelection
		}
	case PublicationBelowThreshold:
		if s.verifiedCount == 0 || hasSelected || s.belowThresholdCount != s.verifiedCount {
			return ErrInvalidPublicationSelection
		}
	case PublicationAdvisoryReady:
		if !hasSelected || s.independenceLevel < s.policy.MinimumIndependence() || s.policy.BlocksOnInconclusive() && s.inconclusiveCount != 0 {
			return ErrInvalidPublicationSelection
		}
	}
	previous := VerifiedFinding{}
	seen := map[string]struct{}{}
	for group, findings := range [][]VerifiedFinding{s.inlineFindings, s.summaryOnlyFindings} {
		for _, finding := range findings {
			if finding.Validate() != nil || finding.snapshotIdentity != s.snapshotIdentity || severityRank(finding.Severity()) < severityRank(s.policy.MinimumSeverity()) || previous.Identity() != "" && publicationFindingLess(finding, previous) || group == 0 && finding.Side() != LineSideHead {
				return ErrInvalidPublicationSelection
			}
			if _, exists := seen[finding.Identity()]; exists {
				return ErrInvalidPublicationSelection
			}
			seen[finding.Identity()] = struct{}{}
			previous = finding
		}
	}
	expectedInline, err := publishableFindings(s.inlineFindings)
	if err != nil || !equalPublishableFindings(expectedInline, s.inlineProjection) {
		return ErrInvalidPublicationSelection
	}
	expectedSummary, err := publishableFindings(s.summaryOnlyFindings)
	if err != nil || !equalPublishableFindings(expectedSummary, s.summaryOnlyProjection) {
		return ErrInvalidPublicationSelection
	}
	if s.identity != derivePublicationSelectionIdentity(s) {
		return ErrInvalidPublicationSelection
	}
	return nil
}

func equalPublishableFindings(left, right []PublishableFinding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func derivePublicationSelectionIdentity(selection PublicationSelection) string {
	inline := verifiedFindingIdentities(selection.inlineFindings)
	summary := verifiedFindingIdentities(selection.summaryOnlyFindings)
	encoded, _ := json.Marshal(struct {
		Contract     string   `json:"contract"`
		Version      int      `json:"version"`
		Status       string   `json:"status"`
		Policy       string   `json:"policy"`
		Receipt      string   `json:"receipt"`
		Set          string   `json:"set"`
		Scope        string   `json:"scope"`
		Snapshot     string   `json:"snapshot"`
		Independence string   `json:"independence"`
		Verified     uint8    `json:"verified"`
		Rejected     uint8    `json:"rejected"`
		Inconclusive uint8    `json:"inconclusive"`
		Below        uint8    `json:"below"`
		Inline       []string `json:"inline"`
		Summary      []string `json:"summary"`
	}{"open-trestle/publication-selection", 1, selection.status.String(), selection.policy.Identity(), selection.verificationReceiptIdentity, selection.verifiedFindingSetIdentity, selection.reviewScopeIdentity, selection.snapshotIdentity, selection.independenceLevel.String(), selection.verifiedCount, selection.rejectedCount, selection.inconclusiveCount, selection.belowThresholdCount, inline, summary})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// PublicationReadiness selects advisory output but never grants an external effect.
type PublicationReadiness struct {
	identity                    string
	status                      PublicationReadinessStatus
	policy                      PublicationPolicy
	verificationReceiptIdentity string
	verifiedFindingSetIdentity  string
	selectionIdentity           string
	selection                   PublicationSelection
	contentScanReceiptIdentity  string
	contentScanReceipt          PublicationContentScanReceipt
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

func EvaluatePublicationReadiness(policy PublicationPolicy, receipt IndependentVerificationReceipt, set VerifiedFindingSet, verificationContext PublicationVerificationContext, selection PublicationSelection, contentScan PublicationContentScanReceipt) (PublicationReadiness, error) {
	expected, err := SelectPublicationFindings(policy, receipt, set)
	if err != nil || selection.Validate() != nil || selection.Identity() != expected.Identity() {
		return PublicationReadiness{}, ErrInvalidPublicationSelection
	}
	if selection.Status() == PublicationAdvisoryReady {
		if err := contentScan.validateFor(receipt, set, verificationContext, selection); err != nil {
			return PublicationReadiness{}, err
		}
	} else if contentScan.Identity() != "" {
		return PublicationReadiness{}, ErrPublicationContentScanMismatch
	}
	r := PublicationReadiness{
		status: selection.Status(), policy: policy, verificationReceiptIdentity: receipt.Identity(),
		verifiedFindingSetIdentity: set.Identity(), selectionIdentity: selection.Identity(), selection: selection,
		contentScanReceiptIdentity: contentScan.Identity(), contentScanReceipt: contentScan,
		reviewScopeIdentity: receipt.ReviewScopeIdentity(), snapshotIdentity: set.SnapshotIdentity(), generationContextIdentity: receipt.GenerationContextIdentity(),
		independenceLevel: receipt.IndependenceLevel(), verifiedCount: set.VerifiedCount(), rejectedCount: set.RejectedCount(), inconclusiveCount: set.InconclusiveCount(),
		belowThresholdCount: selection.BelowThresholdCount(), inlineFindings: selection.InlineFindings(), summaryOnlyFindings: selection.SummaryOnlyFindings(),
	}
	if selection.Status() != PublicationAdvisoryReady {
		r.inlineFindings, r.summaryOnlyFindings = nil, nil
	}
	if selection.Status() == PublicationAdvisoryReady {
		switch {
		case contentScan.Initial().MatchCount != 0:
			r.status = PublicationBlockedSensitiveContent
			r.inlineFindings, r.summaryOnlyFindings = nil, nil
		case contentScan.HasInstructionRisk():
			r.status = PublicationBlockedInstructionRisk
			r.inlineFindings, r.summaryOnlyFindings = nil, nil
		}
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
func (r PublicationReadiness) SelectionIdentity() string       { return r.selectionIdentity }
func (r PublicationReadiness) Selection() PublicationSelection { return r.selection }
func (r PublicationReadiness) ContentScanReceiptIdentity() string {
	return r.contentScanReceiptIdentity
}
func (r PublicationReadiness) ContentScanReceipt() PublicationContentScanReceipt {
	return r.contentScanReceipt
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
	for _, id := range []string{r.verificationReceiptIdentity, r.verifiedFindingSetIdentity, r.selectionIdentity, r.reviewScopeIdentity, r.snapshotIdentity, r.generationContextIdentity} {
		if !validCandidateDigest(id) {
			return ErrInvalidPublicationReadiness
		}
	}
	if r.selection.Validate() != nil || r.selection.Identity() != r.selectionIdentity || r.selection.PolicyIdentity() != r.policy.Identity() || r.selection.VerificationReceiptIdentity() != r.verificationReceiptIdentity || r.selection.VerifiedFindingSetIdentity() != r.verifiedFindingSetIdentity || r.selection.ReviewScopeIdentity() != r.reviewScopeIdentity || r.selection.SnapshotIdentity() != r.snapshotIdentity || r.selection.verifiedCount != r.verifiedCount || r.selection.rejectedCount != r.rejectedCount || r.selection.inconclusiveCount != r.inconclusiveCount || r.selection.belowThresholdCount != r.belowThresholdCount {
		return ErrInvalidPublicationReadiness
	}
	requiresScan := r.selection.Status() == PublicationAdvisoryReady
	if !requiresScan {
		if r.contentScanReceiptIdentity != "" || r.contentScanReceipt.Identity() != "" || r.status != r.selection.Status() {
			return ErrInvalidPublicationReadiness
		}
	} else if !validCandidateDigest(r.contentScanReceiptIdentity) || r.contentScanReceipt.Validate() != nil || r.contentScanReceipt.Identity() != r.contentScanReceiptIdentity || r.contentScanReceipt.VerifiedFindingSetIdentity() != r.verifiedFindingSetIdentity || r.contentScanReceipt.SelectionIdentity() != r.selectionIdentity || r.contentScanReceipt.PolicyIdentity() != r.policy.Identity() || r.contentScanReceipt.ReviewScopeIdentity() != r.reviewScopeIdentity {
		return ErrInvalidPublicationReadiness
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
	has := len(r.inlineFindings) != 0 || len(r.summaryOnlyFindings) != 0
	switch r.status {
	case PublicationBlockedIndependence:
		if r.selection.Status() != PublicationBlockedIndependence || has {
			return ErrInvalidPublicationReadiness
		}
	case PublicationBlockedSensitiveContent:
		if r.selection.Status() != PublicationAdvisoryReady || has || r.contentScanReceipt.Initial().MatchCount == 0 {
			return ErrInvalidPublicationReadiness
		}
	case PublicationBlockedInstructionRisk:
		if r.selection.Status() != PublicationAdvisoryReady || has || r.contentScanReceipt.Initial().MatchCount != 0 || !r.contentScanReceipt.HasInstructionRisk() {
			return ErrInvalidPublicationReadiness
		}
	case PublicationBlockedInconclusive:
		if r.selection.Status() != PublicationBlockedInconclusive || has {
			return ErrInvalidPublicationReadiness
		}
	case PublicationNoVerifiedFindings:
		if r.selection.Status() != PublicationNoVerifiedFindings || has {
			return ErrInvalidPublicationReadiness
		}
	case PublicationBelowThreshold:
		if r.selection.Status() != PublicationBelowThreshold || r.verifiedCount == 0 || r.belowThresholdCount != r.verifiedCount || has {
			return ErrInvalidPublicationReadiness
		}
	case PublicationAdvisoryReady:
		if r.selection.Status() != PublicationAdvisoryReady || r.contentScanReceipt.Initial().MatchCount != 0 || r.contentScanReceipt.HasInstructionRisk() || len(r.inlineFindings)+len(r.summaryOnlyFindings) == 0 || !equalFindingIdentities(r.inlineFindings, r.selection.inlineFindings) || !equalFindingIdentities(r.summaryOnlyFindings, r.selection.summaryOnlyFindings) {
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
func equalFindingIdentities(left, right []VerifiedFinding) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Identity() != right[index].Identity() {
			return false
		}
	}
	return true
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

// publicationFindingLess orders head findings before findings on removed base
// lines, then by severity, path, and lines. Head-only order is unchanged.
func publicationFindingLess(a, b VerifiedFinding) bool {
	if a.Side() != b.Side() {
		return a.Side() < b.Side()
	}
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
		Selection         string   `json:"selection"`
		ContentScan       string   `json:"content_scan"`
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
		Set: r.verifiedFindingSetIdentity, Selection: r.selectionIdentity, ContentScan: r.contentScanReceiptIdentity, Scope: r.reviewScopeIdentity, Snapshot: r.snapshotIdentity, GenerationContext: r.generationContextIdentity,
		Independence: r.independenceLevel.String(), Verified: r.verifiedCount,
		Rejected: r.rejectedCount, Inconclusive: r.inconclusiveCount, Below: r.belowThresholdCount,
		Inline: inline, Summary: summary,
	}
	b, _ := json.Marshal(v)
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func verifiedFindingIdentities(findings []VerifiedFinding) []string {
	identities := make([]string, len(findings))
	for index, finding := range findings {
		identities[index] = finding.Identity()
	}
	return identities
}
