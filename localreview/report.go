package localreview

import (
	"fmt"
	"slices"

	"github.com/georgejieh/open-trestle/diagnostics"
)

// ExitPolicy selects how a terminal result maps to the process exit status. The
// default policy preserves the historical mapping (see ExitCode). The other
// policies exist for headless CI steps and never change the result itself: the
// result still reports comprehensive_clearance=false, its limitations and its
// coverage, so exit 0 is a pipeline decision and never a repository clearance.
type ExitPolicy string

const (
	// ExitPolicyDefault is the historical mapping: 4 blocked, 3 inconclusive, 1 error.
	ExitPolicyDefault ExitPolicy = "default"
	// ExitPolicyFindings exits 0 when the review ran to completion and no
	// verified high/critical finding exists; it keeps the historical code when a
	// blocking finding exists or the review could not run to completion.
	ExitPolicyFindings ExitPolicy = "findings"
	// ExitPolicyStrict exits 0 only when the review ran to completion with no
	// candidates at all, no verified findings of any severity and no coverage gap.
	ExitPolicyStrict ExitPolicy = "strict"
	// ExitPolicyAlwaysZero exits 0 whenever a valid terminal result was produced,
	// including refused and failed runs. It is for advisory-only steps.
	ExitPolicyAlwaysZero ExitPolicy = "always-zero"
)

// ParseExitPolicy accepts exactly the documented policy names.
func ParseExitPolicy(value string) (ExitPolicy, bool) {
	switch policy := ExitPolicy(value); policy {
	case ExitPolicyDefault, ExitPolicyFindings, ExitPolicyStrict, ExitPolicyAlwaysZero:
		return policy, true
	}
	return "", false
}

// ExitCodeFor maps the result through policy. An invalid result is always 1.
func (r Result) ExitCodeFor(policy ExitPolicy) int {
	if !r.valid {
		return 1
	}
	completed := r.wire.RunStatus == "succeeded"
	switch policy {
	case ExitPolicyAlwaysZero:
		return 0
	case ExitPolicyFindings:
		if completed && !r.hasBlockingFinding() {
			return 0
		}
	case ExitPolicyStrict:
		if completed && r.wire.Status == "no_candidates" {
			return 0
		}
	}
	return r.ExitCode()
}

// hasBlockingFinding reports a verified high or critical finding that the
// change introduced. Diagnostics map both to the error severity. A
// pre-existing finding never blocks. A findings status whose diagnostics are
// unavailable is treated as blocking rather than guessed to be minor.
func (r Result) hasBlockingFinding() bool {
	if r.wire.Status != "findings" {
		return false
	}
	findings := r.diagnostics.Findings()
	if len(findings) == 0 {
		return true
	}
	for _, finding := range findings {
		if finding.Severity() == diagnostics.SeverityError && !slices.Contains(r.wire.PreExisting, finding.Identity()) {
			return true
		}
	}
	return false
}

// ReportFinding is one independently verified finding. Title, Claim, location and
// severity were checked by the verifier. Category and Fix are the generator's
// advisory label and unverified model text: the verifier did not check them and
// nothing applies them.
type ReportFinding struct {
	Identity       string
	SourceIdentity string
	Fingerprint    string
	Title          string
	Claim          string
	Severity       diagnostics.Severity
	Path           string
	StartLine      uint32
	EndLine        uint32
	EvidenceIDs    []string
	Category       string
	Fix            string
	// Side tells whether Path, StartLine and EndLine are head lines or removed
	// lines of the base revision. HeadLine is, for a base-side finding at a
	// deletion point, the head line beside which the lines were removed; 0
	// when none remains, such as for a removed file.
	Side     diagnostics.LineSide
	HeadLine uint32
	// PreExisting marks a finding located only on unchanged lines that the
	// change did not touch (see the result's pre_existing list). It never
	// blocks CI.
	PreExisting bool
	// Rank is the 1-based rank of the distinct finding this finding is or was
	// merged into. DuplicateOf names that finding's representative when this
	// finding was merged into it, and is empty for a representative.
	Rank        int
	DuplicateOf string
}

// SourceText renders a finding location for text output. Removed base lines
// are named as such, with the head line beside them when one remains, so their
// numbers are never read as head lines.
func SourceText(path string, side diagnostics.LineSide, startLine, endLine, headLine uint32) string {
	if side == diagnostics.LineSideHead {
		return fmt.Sprintf("%s:%d-%d", path, startLine, endLine)
	}
	text := fmt.Sprintf("%s removed base lines %d-%d", path, startLine, endLine)
	if headLine != 0 {
		text += fmt.Sprintf(" (beside head line %d)", headLine)
	}
	return text
}

// ReportOmission counts bounded source omissions by reason.
type ReportOmission struct {
	Reason string
	Count  uint32
}

// Report is a read-only projection of a terminal result for exporters. It carries
// no prompt, source text, credential or configuration path.
type Report struct {
	Status        string
	CIDisposition string
	RunStatus     string
	Failure       string
	Independence  string
	Limitations   []string
	HeadRevision  string
	DiagnosticSet string

	// Run identities and usage, for exporters that summarize several runs. They
	// are opaque content identities, never paths, prompts or credentials.
	ReviewRunID, ScopeIdentity, PlanIdentity, ContextIdentity string
	GenerationRoute, VerificationRoute                        string
	SpecialistProfileID, SpecialistProfileIdentity            string
	UsageKnown                                                bool
	ActualCostMicroUSD                                        uint64
	// TokenUsage is a version 6 result's token usage, and nil for a result
	// that reports none.
	TokenUsage *TokenUsage

	// FailureTask, FailureDetail and FailureHint explain a run that did not
	// succeed: the first failed task key, an observed refinement such as
	// model_output_exhausted, and a one-line plain-language hint.
	FailureTask, FailureDetail, FailureHint string
	// ContextShortfall carries the counts of a route_context_insufficient
	// failure; it is nil otherwise.
	ContextShortfall *ReportContextShortfall

	Findings []ReportFinding
	// Ranked holds the distinct findings in rank order, each with the
	// duplicates merged into it.
	Ranked []MergedFinding

	HasVerifiedSet                                bool
	Candidates, Verified, Rejected, Inconclusive  uint16
	HasSourceCoverage                             bool
	SourceAnalyzed, SourceSelected, SourceOmitted uint32
	Omissions                                     []ReportOmission
	// InstructionContextOmitted counts repository instruction files not supplied
	// as advisory context. It is not part of SourceOmitted and never makes a
	// review incomplete.
	InstructionContextOmitted uint32
	// AgentConfigurationSources and InstructionLikeSources count generation
	// sources flagged as repository AI material or instruction-like text. They
	// are attention signals; flagged sources are reviewed as code.
	AgentConfigurationSources, InstructionLikeSources int
	// StyleAdvice is the result's style advice; it is never a finding.
	StyleAdvice StyleAdvice
	// Walkthrough is a direct run's walkthrough, or nil.
	Walkthrough *Walkthrough
}

// Report projects the result for an exporter such as SARIF. It fails for an
// invalid result or a guidance entry that does not bind a diagnostic finding.
func (r Result) Report() (Report, error) {
	if !r.valid || r.wire.ComprehensiveClearance {
		return Report{}, ErrInvalidResult
	}
	report := Report{
		Status: r.wire.Status, CIDisposition: r.wire.CI, RunStatus: r.wire.RunStatus, Failure: r.wire.Failure,
		Independence: r.wire.Independence, Limitations: append([]string{}, r.wire.Limitations...),
		Findings: []ReportFinding{}, Omissions: []ReportOmission{},
		ReviewRunID: r.wire.Run, ScopeIdentity: r.wire.Scope, PlanIdentity: r.wire.Plan, ContextIdentity: r.wire.Context,
		GenerationRoute: r.wire.GenerationRoute, VerificationRoute: r.wire.VerificationRoute,
		UsageKnown: r.wire.UsageKnown, ActualCostMicroUSD: r.wire.ActualCostMicroUSD,
		InstructionContextOmitted: r.wire.InstructionContextOmitted,
		AgentConfigurationSources: r.wire.AgentConfigurationSources, InstructionLikeSources: r.wire.InstructionLikeSources,
		StyleAdvice: r.StyleAdvice(),
	}
	if class, task, detail, hint := r.failureSummary(); class != "" {
		report.FailureTask, report.FailureDetail, report.FailureHint = task, detail, hint
		if detail == FailureDetailRouteContextInsufficient && r.wire.ContextShortfall != nil {
			s := *r.wire.ContextShortfall
			report.ContextShortfall = &ReportContextShortfall{RequiredTokens: s.RequiredTokens, EstimatedInputTokens: s.EstimatedInputTokens, MaxOutputTokens: s.MaxOutputTokens, DeclaredContextTokens: s.DeclaredContextTokens}
		}
	}
	if r.wire.Specialist != nil {
		report.SpecialistProfileID, report.SpecialistProfileIdentity = r.wire.Specialist.ProfileID, r.wire.Specialist.ProfileIdentity
	}
	if r.wire.TokenUsage != nil {
		usage := r.wire.TokenUsage.clone()
		report.TokenUsage = &usage
	}
	if r.wire.Walkthrough != nil {
		report.Walkthrough = r.wire.Walkthrough.clone()
	}
	set := r.diagnostics
	if set.Identity() != "" {
		report.HeadRevision, report.DiagnosticSet = set.HeadRevision(), set.Identity()
	}
	guidance := make(map[string]findingGuidanceWire, len(r.wire.Guidance))
	for _, value := range r.wire.Guidance {
		guidance[value.FindingIdentity] = value
	}
	for _, finding := range set.Findings() {
		item := ReportFinding{
			Identity: finding.Identity(), SourceIdentity: finding.SourceIdentity(), Fingerprint: finding.Fingerprint(),
			Title: finding.Title(), Claim: finding.Message(), Severity: finding.Severity(), Path: finding.Path(),
			StartLine: finding.StartLine(), EndLine: finding.EndLine(), EvidenceIDs: finding.EvidenceIDs(),
			Side: finding.Side(), HeadLine: finding.HeadLine(),
		}
		if value, ok := guidance[finding.SourceIdentity()]; ok {
			item.Category = value.Category
			if value.FixAuthority == FixAuthority {
				item.Fix = value.Fix
			}
			delete(guidance, finding.SourceIdentity())
		}
		report.Findings = append(report.Findings, item)
	}
	if len(guidance) != 0 {
		return Report{}, fmt.Errorf("%w: guidance does not bind a diagnostic finding", ErrInvalidResult)
	}
	if err := report.applyJudgement(r.wire); err != nil {
		return Report{}, fmt.Errorf("%w: rank or pre_existing does not cover the diagnostic findings", ErrInvalidResult)
	}
	if set.VerifiedSetIdentity() != "" {
		report.HasVerifiedSet = true
		report.Candidates, report.Verified = set.CandidateCount(), set.VerifiedCount()
		report.Rejected, report.Inconclusive = set.RejectedCount(), set.InconclusiveCount()
	}
	if set.VerificationContextIdentity() != "" {
		report.HasSourceCoverage = true
		report.SourceAnalyzed, report.SourceSelected, report.SourceOmitted = set.SourceAnalyzedCount(), set.SourceSelectedCount(), set.SourceOmittedCount()
		for _, omission := range set.OmissionSummaries() {
			report.Omissions = append(report.Omissions, ReportOmission{Reason: omission.Reason().String(), Count: omission.Count()})
		}
	}
	return report, nil
}

// IncompleteSourceRead reports an incomplete result whose run did not succeed,
// that is, the selected source could not be read to the end. It is not true for a
// completed run with coverage gaps.
func (r Result) IncompleteSourceRead() bool {
	return r.valid && r.wire.Status == "incomplete" && r.wire.RunStatus != "succeeded"
}
