package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/review"
)

const (
	sarifSchemaURI             = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	staticDebugOutputSARIFRule = "static-debug-output"
	verifiedFindingSARIFRule   = "open-trestle-verified-finding"
	maxDiagnosticSARIFBytes    = 4 << 20
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool          `json:"tool"`
	Results    []sarifResult      `json:"results"`
	Properties sarifRunProperties `json:"properties"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string             `json:"id"`
	ShortDescription     sarifMessage       `json:"shortDescription"`
	DefaultConfiguration sarifConfiguration `json:"defaultConfiguration"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID       string                `json:"ruleId"`
	Level        string                `json:"level"`
	Message      sarifMessage          `json:"message"`
	Locations    []sarifLocation       `json:"locations"`
	Fingerprints map[string]string     `json:"fingerprints"`
	Properties   sarifResultProperties `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}

type sarifRunProperties struct {
	Status                review.Outcome  `json:"trestleStatus"`
	Reason                string          `json:"trestleReason,omitempty"`
	FixtureID             string          `json:"trestleFixtureId,omitempty"`
	RequestID             string          `json:"trestleRequestId,omitempty"`
	SnapshotID            string          `json:"trestleSnapshotId,omitempty"`
	Revision              string          `json:"trestleRevision,omitempty"`
	DiagnosticSetID       string          `json:"trestleDiagnosticSetId,omitempty"`
	AnalysisResultID      string          `json:"trestleAnalysisResultId,omitempty"`
	ChangeID              string          `json:"trestleChangeId,omitempty"`
	CheckID               string          `json:"trestleCheckId,omitempty"`
	CheckState            string          `json:"trestleCheckState,omitempty"`
	VerifiedSetID         string          `json:"trestleVerifiedSetId,omitempty"`
	VerificationContextID string          `json:"trestleVerificationContextId,omitempty"`
	SourceCheckID         string          `json:"trestleSourceCheckId,omitempty"`
	CheckAnalysisResultID string          `json:"trestleCheckAnalysisResultId,omitempty"`
	CheckKey              string          `json:"trestleCheckKey,omitempty"`
	CheckRuleVersion      *uint16         `json:"trestleCheckRuleVersion,omitempty"`
	ApplicableFiles       *uint32         `json:"trestleApplicableFiles,omitempty"`
	ApplicableRanges      *uint32         `json:"trestleApplicableRanges,omitempty"`
	CheckedFiles          *uint32         `json:"trestleCheckedFiles,omitempty"`
	CheckedRanges         *uint32         `json:"trestleCheckedRanges,omitempty"`
	MatchCount            *uint32         `json:"trestleMatchCount,omitempty"`
	CandidateCount        *uint16         `json:"trestleCandidateCount,omitempty"`
	VerifiedCount         *uint16         `json:"trestleVerifiedCount,omitempty"`
	RejectedCount         *uint16         `json:"trestleRejectedCount,omitempty"`
	InconclusiveCount     *uint16         `json:"trestleInconclusiveCount,omitempty"`
	SourceAnalyzedCount   *uint32         `json:"trestleSourceAnalyzedCount,omitempty"`
	SourceSelectedCount   *uint32         `json:"trestleSourceSelectedCount,omitempty"`
	SourceOmittedCount    *uint32         `json:"trestleSourceOmittedCount,omitempty"`
	Omissions             []sarifOmission `json:"trestleOmissions,omitempty"`
}

type sarifOmission struct {
	Reason string `json:"reason"`
	Count  uint32 `json:"count"`
}

type sarifResultProperties struct {
	EvidenceID          string   `json:"trestleEvidenceId,omitempty"`
	EvidenceIDs         []string `json:"trestleEvidenceIds,omitempty"`
	EvidenceDigest      string   `json:"trestleEvidenceDigest,omitempty"`
	ObservationIdentity string   `json:"trestleObservationId,omitempty"`
	AnalysisResultID    string   `json:"trestleAnalysisResultId,omitempty"`
	CheckID             string   `json:"trestleCheckId,omitempty"`
}

func runSARIF(fixturePath string, stdout, stderr io.Writer) int {
	evaluation := evaluateLocalCI(fixturePath)
	log, err := buildSARIFLog(evaluation)
	if err != nil {
		fmt.Fprintf(stderr, "build SARIF result: %v\n", err)
		return 1
	}
	return writeJSONResult(log, stdout, stderr, evaluation.exitCode)
}

func buildSARIFLog(evaluation ciEvaluation) (sarifLog, error) {
	result := evaluation.result
	properties := sarifRunProperties{
		Status:     evaluation.outcome,
		Reason:     evaluation.reason,
		FixtureID:  result.FixtureIdentity(),
		RequestID:  result.RequestID(),
		SnapshotID: result.SnapshotIdentity(),
		Revision:   result.Revision(),
	}
	results := make([]sarifResult, 0)
	if evaluation.outcome == review.OutcomeVerified {
		findings := result.Findings()
		items := result.EvidenceItems()
		if len(findings) != len(items) {
			return sarifLog{}, fmt.Errorf("finding and evidence counts differ")
		}
		results = make([]sarifResult, len(findings))
		for i, finding := range findings {
			level, err := sarifLevel(finding.Severity())
			if err != nil {
				return sarifLog{}, err
			}
			sourceRange := finding.SourceRange()
			item := items[i]
			results[i] = sarifResult{
				RuleID:  staticDebugOutputSARIFRule,
				Level:   level,
				Message: sarifMessage{Text: finding.Title()},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(sourceRange.Path())},
						Region: sarifRegion{
							StartLine: sourceRange.StartLine(),
							EndLine:   sourceRange.EndLine(),
						},
					},
				}},
				Fingerprints: map[string]string{"openTrestleFindingId/v1": finding.ID()},
				Properties: sarifResultProperties{
					EvidenceID:     item.ID(),
					EvidenceDigest: item.Digest(),
				},
			}
		}
	}
	return sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "Open Trestle",
				Rules: []sarifRule{{
					ID:                   staticDebugOutputSARIFRule,
					ShortDescription:     sarifMessage{Text: "Debug output left in source"},
					DefaultConfiguration: sarifConfiguration{Level: "warning"},
				}},
			}},
			Results:    results,
			Properties: properties,
		}},
	}, nil
}

func buildDiagnosticSetSARIF(set diagnostics.Set) (sarifLog, error) {
	version := set.SchemaVersion()
	if version != 1 && version != 2 && version != 3 && version != 5 && version != 6 {
		return sarifLog{}, fmt.Errorf("unsupported diagnostic SARIF schema version %d", version)
	}
	if err := set.Validate(); err != nil {
		return sarifLog{}, fmt.Errorf("diagnostic set is invalid: %w", err)
	}
	if version == 1 {
		return buildHistoricalV1DiagnosticSetSARIF(set)
	}
	if version == 2 {
		return buildHistoricalV2DiagnosticSetSARIF(set)
	}
	if version == 3 {
		return buildHistoricalV3DiagnosticSetSARIF(set)
	}
	if version == 5 {
		return buildVerifiedDiagnosticSetSARIF(set)
	}
	return buildDeterministicDiagnosticSetSARIF(set)
}

func buildDeterministicDiagnosticSetSARIF(set diagnostics.Set) (sarifLog, error) {
	if len(set.DeterministicChecks()) != 1 {
		return sarifLog{}, fmt.Errorf("deterministic diagnostic set is invalid")
	}
	check := set.DeterministicChecks()[0]
	observations := set.DeterministicObservations()
	if uint32(len(observations)) != check.MatchCount() {
		return sarifLog{}, fmt.Errorf("deterministic observation count differs")
	}
	results := make([]sarifResult, len(observations))
	for index, observation := range observations {
		level, err := diagnosticSARIFLevel(observation.Severity())
		if err != nil {
			return sarifLog{}, err
		}
		evidence := observation.EvidenceIDs()
		if len(evidence) == 0 || len(evidence) > 16 {
			return sarifLog{}, fmt.Errorf("deterministic observation evidence differs")
		}
		results[index] = sarifResult{RuleID: staticDebugOutputSARIFRule, Level: level, Message: sarifMessage{Text: observation.Title() + ": " + observation.Message()}, Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(observation.Path())}, Region: sarifRegion{StartLine: int(observation.StartLine()), EndLine: int(observation.EndLine())}}}}, Fingerprints: map[string]string{"openTrestleObservationId/v1": observation.Identity()}, Properties: sarifResultProperties{EvidenceIDs: evidence, ObservationIdentity: observation.Identity(), AnalysisResultID: set.AnalysisResultIdentity(), CheckID: check.Identity()}}
	}
	return sarifLog{Schema: sarifSchemaURI, Version: "2.1.0", Runs: []sarifRun{{Tool: sarifTool{Driver: sarifDriver{Name: "Open Trestle", Rules: []sarifRule{{ID: staticDebugOutputSARIFRule, ShortDescription: sarifMessage{Text: "Debug output left in source"}, DefaultConfiguration: sarifConfiguration{Level: "warning"}}}}}, Results: results, Properties: sarifRunProperties{Status: review.OutcomeInconclusive, Reason: "deterministic_check_" + check.State().String(), SnapshotID: set.SnapshotIdentity(), Revision: set.HeadRevision(), DiagnosticSetID: set.Identity(), AnalysisResultID: set.AnalysisResultIdentity(), ChangeID: check.ChangeIdentity(), CheckID: check.Identity(), CheckState: check.State().String()}}}}, nil
}

// Version 1 has findings but records neither source coverage nor candidate accounting.
func buildHistoricalV1DiagnosticSetSARIF(set diagnostics.Set) (sarifLog, error) {
	findings := set.Findings()
	results := make([]sarifResult, len(findings))
	for i, finding := range findings {
		level, err := diagnosticSARIFLevel(finding.Severity())
		if err != nil {
			return sarifLog{}, err
		}
		results[i] = sarifResult{
			RuleID: verifiedFindingSARIFRule, Level: level,
			Message: sarifMessage{Text: finding.Title() + ": " + finding.Message()},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(finding.Path())},
				Region:           sarifRegion{StartLine: int(finding.StartLine()), EndLine: int(finding.EndLine())},
			}}},
			Fingerprints: map[string]string{
				"openTrestleVerifiedFindingId/v1":  finding.Identity(),
				"openTrestleFindingFingerprint/v1": finding.Fingerprint(),
			},
			Properties: sarifResultProperties{EvidenceIDs: finding.EvidenceIDs()},
		}
	}
	rules := make([]sarifRule, 0, 1)
	if len(findings) != 0 {
		rules = append(rules, sarifRule{
			ID:                   verifiedFindingSARIFRule,
			ShortDescription:     sarifMessage{Text: "Independently verified finding"},
			DefaultConfiguration: sarifConfiguration{Level: "warning"},
		})
	}
	log := sarifLog{Schema: sarifSchemaURI, Version: "2.1.0", Runs: []sarifRun{{
		Tool:    sarifTool{Driver: sarifDriver{Name: "Open Trestle", Rules: rules}},
		Results: results,
		Properties: sarifRunProperties{
			Status:     review.OutcomeInconclusive,
			Reason:     "review status is advisory; no approval asserted; source coverage unavailable; candidate accounting unavailable",
			SnapshotID: set.SnapshotIdentity(), Revision: set.HeadRevision(), DiagnosticSetID: set.Identity(),
			VerifiedSetID: set.VerifiedSetIdentity(),
		},
	}}}
	// The writer adds one newline. Reject the entire log before writing any bytes.
	encoded, err := json.Marshal(log)
	if err != nil {
		return sarifLog{}, fmt.Errorf("encode version 1 SARIF: %w", err)
	}
	if len(encoded)+1 > maxDiagnosticSARIFBytes {
		return sarifLog{}, fmt.Errorf("version 1 SARIF exceeds %d-byte limit", maxDiagnosticSARIFBytes)
	}
	return log, nil
}

// Version 2 records candidate accounting but not source coverage.
func buildHistoricalV2DiagnosticSetSARIF(set diagnostics.Set) (sarifLog, error) {
	findings := set.Findings()
	results := make([]sarifResult, len(findings))
	for i, finding := range findings {
		level, err := diagnosticSARIFLevel(finding.Severity())
		if err != nil {
			return sarifLog{}, err
		}
		results[i] = sarifResult{
			RuleID: verifiedFindingSARIFRule, Level: level,
			Message: sarifMessage{Text: finding.Title() + ": " + finding.Message()},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(finding.Path())},
				Region:           sarifRegion{StartLine: int(finding.StartLine()), EndLine: int(finding.EndLine())},
			}}},
			Fingerprints: map[string]string{
				"openTrestleVerifiedFindingId/v1":  finding.Identity(),
				"openTrestleFindingFingerprint/v1": finding.Fingerprint(),
			},
			Properties: sarifResultProperties{EvidenceIDs: finding.EvidenceIDs()},
		}
	}
	rules := make([]sarifRule, 0, 1)
	if len(findings) != 0 {
		rules = append(rules, sarifRule{
			ID:                   verifiedFindingSARIFRule,
			ShortDescription:     sarifMessage{Text: "Independently verified finding"},
			DefaultConfiguration: sarifConfiguration{Level: "warning"},
		})
	}
	reason := "review status is advisory; no approval asserted; source coverage unavailable"
	if set.InconclusiveCount() > 0 {
		reason += "; candidate verification inconclusive"
	}
	if set.RejectedCount() > 0 {
		reason += "; rejected candidates"
	}
	log := sarifLog{Schema: sarifSchemaURI, Version: "2.1.0", Runs: []sarifRun{{
		Tool:    sarifTool{Driver: sarifDriver{Name: "Open Trestle", Rules: rules}},
		Results: results,
		Properties: sarifRunProperties{
			Status:     review.OutcomeInconclusive,
			Reason:     reason,
			SnapshotID: set.SnapshotIdentity(), Revision: set.HeadRevision(), DiagnosticSetID: set.Identity(),
			VerifiedSetID:  set.VerifiedSetIdentity(),
			CandidateCount: sarifPointer(set.CandidateCount()), VerifiedCount: sarifPointer(set.VerifiedCount()),
			RejectedCount: sarifPointer(set.RejectedCount()), InconclusiveCount: sarifPointer(set.InconclusiveCount()),
		},
	}}}
	// The writer adds one newline. Reject the entire log before writing any bytes.
	encoded, err := json.Marshal(log)
	if err != nil {
		return sarifLog{}, fmt.Errorf("encode version 2 SARIF: %w", err)
	}
	if len(encoded)+1 > maxDiagnosticSARIFBytes {
		return sarifLog{}, fmt.Errorf("version 2 SARIF exceeds %d-byte limit", maxDiagnosticSARIFBytes)
	}
	return log, nil
}

// Version 3 records source selection counts but not omission reasons.
func buildHistoricalV3DiagnosticSetSARIF(set diagnostics.Set) (sarifLog, error) {
	findings := set.Findings()
	results := make([]sarifResult, len(findings))
	for i, finding := range findings {
		level, err := diagnosticSARIFLevel(finding.Severity())
		if err != nil {
			return sarifLog{}, err
		}
		results[i] = sarifResult{
			RuleID: verifiedFindingSARIFRule, Level: level,
			Message: sarifMessage{Text: finding.Title() + ": " + finding.Message()},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(finding.Path())},
				Region:           sarifRegion{StartLine: int(finding.StartLine()), EndLine: int(finding.EndLine())},
			}}},
			Fingerprints: map[string]string{
				"openTrestleVerifiedFindingId/v1":  finding.Identity(),
				"openTrestleFindingFingerprint/v1": finding.Fingerprint(),
			},
			Properties: sarifResultProperties{EvidenceIDs: finding.EvidenceIDs()},
		}
	}
	rules := make([]sarifRule, 0, 1)
	if len(findings) != 0 {
		rules = append(rules, sarifRule{
			ID:                   verifiedFindingSARIFRule,
			ShortDescription:     sarifMessage{Text: "Independently verified finding"},
			DefaultConfiguration: sarifConfiguration{Level: "warning"},
		})
	}
	reason := "review status is advisory; no approval asserted"
	if set.InconclusiveCount() > 0 {
		reason += "; candidate verification inconclusive"
	}
	if set.RejectedCount() > 0 {
		reason += "; rejected candidates"
	}
	if set.SourceOmittedCount() > 0 {
		reason += "; source selection partial; omission reasons unavailable"
	}
	log := sarifLog{Schema: sarifSchemaURI, Version: "2.1.0", Runs: []sarifRun{{
		Tool:    sarifTool{Driver: sarifDriver{Name: "Open Trestle", Rules: rules}},
		Results: results,
		Properties: sarifRunProperties{
			Status:     review.OutcomeInconclusive,
			Reason:     reason,
			SnapshotID: set.SnapshotIdentity(), Revision: set.HeadRevision(), DiagnosticSetID: set.Identity(),
			VerifiedSetID: set.VerifiedSetIdentity(), VerificationContextID: set.VerificationContextIdentity(),
			CandidateCount: sarifPointer(set.CandidateCount()), VerifiedCount: sarifPointer(set.VerifiedCount()),
			RejectedCount: sarifPointer(set.RejectedCount()), InconclusiveCount: sarifPointer(set.InconclusiveCount()),
			SourceAnalyzedCount: sarifPointer(set.SourceAnalyzedCount()),
			SourceSelectedCount: sarifPointer(set.SourceSelectedCount()),
			SourceOmittedCount:  sarifPointer(set.SourceOmittedCount()),
		},
	}}}
	// The writer adds one newline. Reject the entire log before writing any bytes.
	encoded, err := json.Marshal(log)
	if err != nil {
		return sarifLog{}, fmt.Errorf("encode version 3 SARIF: %w", err)
	}
	if len(encoded)+1 > maxDiagnosticSARIFBytes {
		return sarifLog{}, fmt.Errorf("version 3 SARIF exceeds %d-byte limit", maxDiagnosticSARIFBytes)
	}
	return log, nil
}

// Version 5 findings are independently verified diagnostics, not deterministic observations.
// A check match has no location in this schema and must not generate a result.
func buildVerifiedDiagnosticSetSARIF(set diagnostics.Set) (sarifLog, error) {
	checks := set.DeterministicChecks()
	if len(checks) != 1 {
		return sarifLog{}, fmt.Errorf("version 5 diagnostic check is invalid")
	}
	check := checks[0]
	findings := set.Findings()
	results := make([]sarifResult, len(findings))
	for i, finding := range findings {
		level, err := diagnosticSARIFLevel(finding.Severity())
		if err != nil {
			return sarifLog{}, err
		}
		results[i] = sarifResult{
			RuleID: verifiedFindingSARIFRule, Level: level,
			Message: sarifMessage{Text: finding.Title() + ": " + finding.Message()},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(finding.Path())},
				Region:           sarifRegion{StartLine: int(finding.StartLine()), EndLine: int(finding.EndLine())},
			}}},
			Fingerprints: map[string]string{
				"openTrestleVerifiedFindingId/v1":  finding.Identity(),
				"openTrestleFindingFingerprint/v1": finding.Fingerprint(),
			},
			Properties: sarifResultProperties{EvidenceIDs: finding.EvidenceIDs()},
		}
	}
	omissions := make([]sarifOmission, 0, len(set.OmissionSummaries()))
	for _, summary := range set.OmissionSummaries() {
		omissions = append(omissions, sarifOmission{Reason: summary.Reason().String(), Count: summary.Count()})
	}
	// Whole-log status does not approve a run, even when all recorded axes are complete.
	reason := "review status is advisory; no approval asserted"
	if set.InconclusiveCount() > 0 {
		reason += "; candidate verification inconclusive"
	}
	if set.RejectedCount() > 0 {
		reason += "; rejected candidates"
	}
	if set.SourceOmittedCount() > 0 {
		reason += "; source omission"
	}
	if check.State() != diagnostics.CheckPassed {
		reason += "; deterministic check " + check.State().String()
	}
	if !check.Complete() {
		reason += "; deterministic scan coverage incomplete"
	}
	properties := sarifRunProperties{
		Status: review.OutcomeInconclusive, Reason: reason,
		SnapshotID: set.SnapshotIdentity(), Revision: set.HeadRevision(), DiagnosticSetID: set.Identity(),
		VerifiedSetID: set.VerifiedSetIdentity(), VerificationContextID: set.VerificationContextIdentity(),
		ChangeID: check.ChangeIdentity(), CheckID: check.Identity(), CheckState: check.State().String(),
		SourceCheckID: check.SourceCheckIdentity(), CheckAnalysisResultID: check.AnalysisResultIdentity(),
		CheckKey: check.Key(), CheckRuleVersion: sarifPointer(check.RuleVersion()),
		ApplicableFiles: sarifPointer(check.ApplicableFiles()), ApplicableRanges: sarifPointer(check.ApplicableRanges()),
		CheckedFiles: sarifPointer(check.CheckedFiles()), CheckedRanges: sarifPointer(check.CheckedRanges()),
		MatchCount: sarifPointer(check.MatchCount()), CandidateCount: sarifPointer(set.CandidateCount()),
		VerifiedCount: sarifPointer(set.VerifiedCount()), RejectedCount: sarifPointer(set.RejectedCount()),
		InconclusiveCount:   sarifPointer(set.InconclusiveCount()),
		SourceAnalyzedCount: sarifPointer(set.SourceAnalyzedCount()),
		SourceSelectedCount: sarifPointer(set.SourceSelectedCount()),
		SourceOmittedCount:  sarifPointer(set.SourceOmittedCount()), Omissions: omissions,
	}
	rules := make([]sarifRule, 0, 1)
	if len(findings) != 0 {
		rules = append(rules, sarifRule{
			ID:                   verifiedFindingSARIFRule,
			ShortDescription:     sarifMessage{Text: "Independently verified finding"},
			DefaultConfiguration: sarifConfiguration{Level: "warning"},
		})
	}
	log := sarifLog{Schema: sarifSchemaURI, Version: "2.1.0", Runs: []sarifRun{{
		Tool:    sarifTool{Driver: sarifDriver{Name: "Open Trestle", Rules: rules}},
		Results: results, Properties: properties,
	}}}
	// writeJSONResult marshals this unchanged log and appends one newline.
	// Do not truncate results: failure is safer than a partial finding set.
	encoded, err := json.Marshal(log)
	if err != nil {
		return sarifLog{}, fmt.Errorf("encode version 5 SARIF: %w", err)
	}
	if len(encoded)+1 > maxDiagnosticSARIFBytes {
		return sarifLog{}, fmt.Errorf("version 5 SARIF exceeds %d-byte limit", maxDiagnosticSARIFBytes)
	}
	return log, nil
}

func sarifPointer[T any](value T) *T { return &value }

func diagnosticSARIFLevel(severity diagnostics.Severity) (string, error) {
	switch severity {
	case diagnostics.SeverityError:
		return "error", nil
	case diagnostics.SeverityWarning:
		return "warning", nil
	case diagnostics.SeverityInformation, diagnostics.SeverityHint:
		return "note", nil
	default:
		return "", fmt.Errorf("unsupported diagnostic severity")
	}
}

func buildLocalGitReviewSARIF(result localGitReviewResult) (sarifLog, error) {
	if result.Contract != "open-trestle/local-git-review-result" || result.SchemaVersion != 1 && result.SchemaVersion != 2 {
		return sarifLog{}, fmt.Errorf("local Git review result contract is invalid")
	}
	if err := validateLocalGitReviewWireEvidence(result.Findings, result.Evidence); err != nil {
		return sarifLog{}, err
	}
	results := make([]sarifResult, len(result.Findings))
	for index, finding := range result.Findings {
		item := result.Evidence[index]
		if len(finding.EvidenceIDs) != 1 || finding.EvidenceIDs[0] != item.ID || finding.Path != item.Path || finding.StartLine != item.StartLine || finding.EndLine != item.EndLine {
			return sarifLog{}, fmt.Errorf("finding and evidence binding differs")
		}
		level, err := sarifLevel(review.Severity(finding.Severity))
		if err != nil {
			return sarifLog{}, err
		}
		results[index] = sarifResult{
			RuleID:  staticDebugOutputSARIFRule,
			Level:   level,
			Message: sarifMessage{Text: finding.Title},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(finding.Path)},
					Region:           sarifRegion{StartLine: finding.StartLine, EndLine: finding.EndLine},
				},
			}},
			Fingerprints: map[string]string{"openTrestleFindingId/v1": finding.ID},
			Properties:   sarifResultProperties{EvidenceID: item.ID, EvidenceDigest: item.Digest},
		}
	}
	outcome := review.OutcomeInconclusive
	reason := string(result.Status)
	if result.Status == localGitReviewStatusFindings {
		outcome = review.OutcomeVerified
		reason = ""
	}
	return sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "Open Trestle",
				Rules: []sarifRule{{
					ID:                   staticDebugOutputSARIFRule,
					ShortDescription:     sarifMessage{Text: "Debug output left in source"},
					DefaultConfiguration: sarifConfiguration{Level: "warning"},
				}},
			}},
			Results:    results,
			Properties: sarifRunProperties{Status: outcome, Reason: reason},
		}},
	}, nil
}

func validateLocalGitReviewWireEvidence(findings []localGitReviewFindingResult, items []localGitReviewEvidenceResult) error {
	if len(findings) != len(items) {
		return fmt.Errorf("finding and evidence counts differ")
	}
	findingIDs := make(map[string]struct{}, len(findings))
	evidenceIDs := make(map[string]struct{}, len(items))
	for index, finding := range findings {
		item := items[index]
		if _, exists := findingIDs[finding.ID]; exists {
			return fmt.Errorf("duplicate finding identity")
		}
		if _, exists := evidenceIDs[item.ID]; exists {
			return fmt.Errorf("duplicate evidence identity")
		}
		if len(finding.EvidenceIDs) != 1 || finding.EvidenceIDs[0] != item.ID || finding.Path != item.Path || finding.StartLine != item.StartLine || finding.EndLine != item.EndLine {
			return fmt.Errorf("finding and evidence binding differs")
		}
		findingIDs[finding.ID] = struct{}{}
		evidenceIDs[item.ID] = struct{}{}
	}
	return nil
}

func sarifLevel(severity review.Severity) (string, error) {
	switch severity {
	case review.SeverityLow:
		return "note", nil
	case review.SeverityMedium:
		return "warning", nil
	case review.SeverityHigh, review.SeverityCritical:
		return "error", nil
	default:
		return "", fmt.Errorf("unsupported finding severity: %q", severity)
	}
}

func sarifArtifactURI(sourcePath string) string {
	return (&url.URL{Path: sourcePath}).String()
}
