package main

import (
	"encoding/json"
	"fmt"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/review"
)

// A terminal result records independent static observations and verified findings.
// Neither a matched check nor an absent verification section is a verified finding.
func buildFinalDiagnosticSetSARIF(set diagnostics.Set) (sarifLog, error) {
	observations := set.DeterministicObservations()
	findings := set.Findings()
	checks := set.DeterministicChecks()
	results := make([]sarifResult, 0, len(observations)+len(findings))
	var notifications []sarifNotification
	rules := make([]sarifRule, 0, 2)
	properties := sarifRunProperties{
		Status: review.OutcomeInconclusive, FinalOutcome: set.Outcome(),
		Reason:           "final review " + string(set.Outcome()) + "; SARIF status is advisory; no approval asserted",
		SourceSnapshotID: set.SnapshotIdentity(), Revision: set.HeadRevision(), DiagnosticSetID: set.Identity(),
	}
	if set.AnalysisResultIdentity() != "" {
		if len(checks) != 1 || uint32(len(observations)) != checks[0].MatchCount() {
			return sarifLog{}, fmt.Errorf("final deterministic observations differ from check")
		}
		check := checks[0]
		properties.AnalysisResultID = set.AnalysisResultIdentity()
		properties.ChangeID = check.ChangeIdentity()
		properties.CheckID = check.Identity()
		properties.CheckState = check.State().String()
		properties.SourceCheckID = check.SourceCheckIdentity()
		properties.CheckAnalysisResultID = check.AnalysisResultIdentity()
		properties.CheckKey = check.Key()
		properties.CheckRuleVersion = sarifPointer(check.RuleVersion())
		properties.ApplicableFiles = sarifPointer(check.ApplicableFiles())
		properties.ApplicableRanges = sarifPointer(check.ApplicableRanges())
		properties.CheckedFiles = sarifPointer(check.CheckedFiles())
		properties.CheckedRanges = sarifPointer(check.CheckedRanges())
		properties.MatchCount = sarifPointer(check.MatchCount())
		if check.State() != diagnostics.CheckPassed {
			properties.Reason += "; deterministic check " + check.State().String()
		}
		if !check.Complete() {
			properties.Reason += "; deterministic scan coverage incomplete"
		}
		if len(observations) != 0 {
			rules = append(rules, sarifRule{ID: staticDebugOutputSARIFRule, ShortDescription: sarifMessage{Text: "Debug output left in source"}, DefaultConfiguration: sarifConfiguration{Level: "warning"}})
		}
		for _, observation := range observations {
			level, err := diagnosticSARIFLevel(observation.Severity())
			if err != nil {
				return sarifLog{}, err
			}
			results = append(results, sarifResult{
				RuleID: staticDebugOutputSARIFRule, Level: level,
				Message: sarifMessage{Text: observation.Title() + ": " + observation.Message()},
				Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(observation.Path())},
					Region:           sarifRegion{StartLine: int(observation.StartLine()), EndLine: int(observation.EndLine())},
				}}},
				Fingerprints: map[string]string{"openTrestleObservationId/v1": observation.Identity()},
				Properties:   sarifResultProperties{EvidenceIDs: observation.EvidenceIDs(), ObservationIdentity: observation.Identity(), AnalysisResultID: set.AnalysisResultIdentity(), CheckID: check.Identity()},
			})
		}
	}
	if set.VerifiedSetIdentity() != "" {
		properties.ReviewSnapshotID = set.ReviewSnapshotIdentity()
		properties.VerifiedSetID = set.VerifiedSetIdentity()
		properties.VerificationContextID = set.VerificationContextIdentity()
		properties.CandidateCount = sarifPointer(set.CandidateCount())
		properties.VerifiedCount = sarifPointer(set.VerifiedCount())
		properties.RejectedCount = sarifPointer(set.RejectedCount())
		properties.InconclusiveCount = sarifPointer(set.InconclusiveCount())
		properties.SourceAnalyzedCount = sarifPointer(set.SourceAnalyzedCount())
		properties.SourceSelectedCount = sarifPointer(set.SourceSelectedCount())
		properties.SourceOmittedCount = sarifPointer(set.SourceOmittedCount())
		if set.InconclusiveCount() != 0 {
			properties.Reason += "; candidate verification inconclusive"
		}
		if set.RejectedCount() != 0 {
			properties.Reason += "; rejected candidates"
		}
		if set.SourceOmittedCount() != 0 {
			properties.Reason += "; source omission"
		}
		for _, omission := range set.OmissionSummaries() {
			properties.Omissions = append(properties.Omissions, sarifOmission{Reason: omission.Reason().String(), Count: omission.Count()})
		}
		if len(findings) != 0 {
			rules = append(rules, sarifRule{ID: verifiedFindingSARIFRule, ShortDescription: sarifMessage{Text: "Independently verified finding"}, DefaultConfiguration: sarifConfiguration{Level: "warning"}})
		}
		verified, unplaced, err := verifiedDiagnosticSARIFResults(findings)
		if err != nil {
			return sarifLog{}, err
		}
		results = append(results, verified...)
		notifications = unplaced
	} else {
		properties.Reason += "; independent verification not recorded"
	}
	log := sarifLog{Schema: sarifSchemaURI, Version: "2.1.0", Runs: []sarifRun{{
		Tool: sarifTool{Driver: sarifDriver{Name: "Open Trestle", Rules: rules}}, Invocations: unplacedFindingInvocations(notifications), Results: results, Properties: properties,
	}}}
	encoded, err := json.Marshal(log)
	if err != nil {
		return sarifLog{}, fmt.Errorf("encode version 7 SARIF: %w", err)
	}
	if len(encoded)+1 > maxDiagnosticSARIFBytes {
		return sarifLog{}, fmt.Errorf("version 7 SARIF exceeds %d-byte limit", maxDiagnosticSARIFBytes)
	}
	return log, nil
}
