package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/localreview"
)

const (
	modelReviewRulePrefix        = "open-trestle/"
	modelReviewUncategorizedRule = modelReviewRulePrefix + "uncategorized"
)

// buildModelReviewSARIF projects a terminal local model-review result into SARIF
// 2.1.0 using the shared SARIF types. Only independently verified findings become
// results. Refused, incomplete, canceled and failed runs produce a valid log with
// zero results, executionSuccessful=false and a notification, so an empty result
// list is never the only signal. Output order is sorted and byte-deterministic.
//
// The fix guidance is carried as the trestleFixGuidance property, not as a SARIF
// fixes[] entry: the SARIF schema requires every fix to hold artifactChanges, and
// this guidance is unverified prose that proposes no machine-applicable change.
func buildModelReviewSARIF(report localreview.Report) (sarifLog, error) {
	return buildModelReviewSARIFWithContributors(report, nil)
}

// buildModelReviewSARIFWithContributors is buildModelReviewSARIF for a merged
// review set: contributors maps a finding identity to the members whose
// duplicate verified findings it represents (the trestleContributors property).
func buildModelReviewSARIFWithContributors(report localreview.Report, contributors map[string][]string) (sarifLog, error) {
	rules := map[string]sarifRule{}
	results := make([]sarifResult, 0, len(report.Findings))
	for _, finding := range report.Findings {
		level, err := diagnosticSARIFLevel(finding.Severity)
		if err != nil {
			return sarifLog{}, err
		}
		ruleID := modelReviewUncategorizedRule
		description := "Independently verified finding"
		if finding.Category != "" {
			ruleID = modelReviewRulePrefix + finding.Category
			description = "Independently verified " + finding.Category + " finding"
		}
		rules[ruleID] = sarifRule{ID: ruleID, ShortDescription: sarifMessage{Text: description}, DefaultConfiguration: sarifConfiguration{Level: "warning"}}
		properties := sarifResultProperties{
			EvidenceIDs: finding.EvidenceIDs, Category: finding.Category, Severity: finding.Severity.String(),
			VerifierIndependence: report.Independence,
		}
		if finding.Fix != "" {
			properties.FixGuidance, properties.FixAuthority = finding.Fix, localreview.FixAuthority
		}
		if labels := contributors[finding.Identity]; len(labels) > 0 {
			properties.Contributors = append([]string(nil), labels...)
		}
		results = append(results, sarifResult{
			RuleID: ruleID, Level: level,
			Message: sarifMessage{Text: finding.Title + ": " + finding.Claim},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(finding.Path)},
				Region:           sarifRegion{StartLine: int(finding.StartLine), EndLine: int(finding.EndLine)},
			}}},
			Fingerprints: map[string]string{"openTrestleVerifiedFindingId/v1": finding.Identity},
			PartialFingerprints: map[string]string{
				// Bound to the reviewed snapshot: identifies this finding in this run.
				"openTrestleFindingFingerprint/v1": finding.Fingerprint,
				// Independent of the snapshot and line numbers, so an unchanged claim at
				// an unchanged path keeps one identity across pushes. Model wording can
				// vary between runs, so cross-run deduplication is best effort.
				"openTrestleContentHash/v1": modelReviewContentHash(finding),
			},
			Properties: properties,
		})
	}
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		ap, bp := a.Locations[0].PhysicalLocation, b.Locations[0].PhysicalLocation
		switch {
		case ap.ArtifactLocation.URI != bp.ArtifactLocation.URI:
			return ap.ArtifactLocation.URI < bp.ArtifactLocation.URI
		case ap.Region.StartLine != bp.Region.StartLine:
			return ap.Region.StartLine < bp.Region.StartLine
		case ap.Region.EndLine != bp.Region.EndLine:
			return ap.Region.EndLine < bp.Region.EndLine
		case a.RuleID != b.RuleID:
			return a.RuleID < b.RuleID
		}
		return a.Fingerprints["openTrestleVerifiedFindingId/v1"] < b.Fingerprints["openTrestleVerifiedFindingId/v1"]
	})
	ruleList := make([]sarifRule, 0, len(rules))
	for _, rule := range rules {
		ruleList = append(ruleList, rule)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	outcome := review.OutcomeInconclusive
	if report.Status == "findings" && len(results) != 0 {
		outcome = review.OutcomeVerified
	}
	clearance := false
	properties := sarifRunProperties{
		Status: outcome, Reason: "model review " + report.Status + "; SARIF status is advisory; no approval asserted",
		Revision: report.HeadRevision, DiagnosticSetID: report.DiagnosticSet,
		ModelReviewStatus: report.Status, CIDisposition: report.CIDisposition, RunStatus: report.RunStatus,
		Failure: report.Failure, VerifierIndependence: report.Independence,
		Limitations: append([]string{}, report.Limitations...), ComprehensiveClearance: &clearance,
	}
	sort.Strings(properties.Limitations)
	if report.HasVerifiedSet {
		properties.CandidateCount = sarifPointer(report.Candidates)
		properties.VerifiedCount = sarifPointer(report.Verified)
		properties.RejectedCount = sarifPointer(report.Rejected)
		properties.InconclusiveCount = sarifPointer(report.Inconclusive)
	}
	if report.HasSourceCoverage {
		properties.SourceAnalyzedCount = sarifPointer(report.SourceAnalyzed)
		properties.SourceSelectedCount = sarifPointer(report.SourceSelected)
		properties.SourceOmittedCount = sarifPointer(report.SourceOmitted)
		for _, omission := range report.Omissions {
			properties.Omissions = append(properties.Omissions, sarifOmission{Reason: omission.Reason, Count: omission.Count})
		}
		sort.Slice(properties.Omissions, func(i, j int) bool { return properties.Omissions[i].Reason < properties.Omissions[j].Reason })
	}
	if report.InstructionContextOmitted > 0 {
		properties.InstructionContextOmittedCount = sarifPointer(report.InstructionContextOmitted)
	}
	if report.AgentConfigurationSources > 0 {
		properties.AgentConfigurationSourceCount = sarifPointer(report.AgentConfigurationSources)
	}
	if report.InstructionLikeSources > 0 {
		properties.InstructionLikeSourceCount = sarifPointer(report.InstructionLikeSources)
	}
	log := sarifLog{Schema: sarifSchemaURI, Version: "2.1.0", Runs: []sarifRun{{
		Tool:        sarifTool{Driver: sarifDriver{Name: "Open Trestle", Rules: ruleList}},
		Invocations: []sarifInvocation{modelReviewInvocation(report, len(results))},
		Results:     results, Properties: properties,
	}}}
	return log, nil
}

func modelReviewContentHash(finding localreview.ReportFinding) string {
	encoded, _ := json.Marshal([]string{"open-trestle/model-review-content/v1", finding.Path, finding.Category, finding.Title, finding.Claim})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func modelReviewInvocation(report localreview.Report, findings int) sarifInvocation {
	completed := report.RunStatus == "succeeded"
	invocation := sarifInvocation{ExecutionSuccessful: completed}
	switch {
	case !completed:
		invocation.ToolExecutionNotifications = []sarifNotification{{Level: "error", Message: sarifMessage{Text: modelReviewNotRunMessage(report)}}}
	case report.Status == "no_candidates":
		invocation.ToolExecutionNotifications = []sarifNotification{{Level: "note", Message: sarifMessage{Text: "The review completed and produced no candidate findings. This is not a clearance: the review is bounded, see the run limitations."}}}
	case report.Status == "incomplete":
		invocation.ToolExecutionNotifications = []sarifNotification{{Level: "warning", Message: sarifMessage{Text: "The review completed with coverage gaps (candidate verification was inconclusive, a candidate was rejected, or source was omitted). Treat the absence of results as unknown, not as clear."}}}
	case findings != 0:
		invocation.ToolExecutionNotifications = []sarifNotification{{Level: "note", Message: sarifMessage{Text: "The review completed. The listed findings were independently verified; the review is still bounded and is not a clearance of the rest of the change."}}}
	}
	return invocation
}

func modelReviewNotRunMessage(report localreview.Report) string {
	var meaning string
	switch report.Status {
	case "refused":
		meaning = "was refused by policy, configuration or a resource limit"
	case "incomplete":
		meaning = "could not read the selected change (for example a base or head commit is missing from a shallow checkout; fetch it or use fetch-depth: 0)"
	case "canceled":
		meaning = "was canceled or timed out"
	default:
		meaning = "failed before a trustworthy result was read back"
	}
	detail := fmt.Sprintf("status=%s run_status=%s", report.Status, report.RunStatus)
	if report.Failure != "" {
		detail += " failure=" + report.Failure
	}
	return "The model review " + meaning + "; no findings were evaluated and this is not a clean result (" + detail + "). Limitations: " + strings.Join(report.Limitations, ", ") + "."
}

// encodeModelReviewSARIF returns canonical, newline-terminated SARIF bytes.
func encodeModelReviewSARIF(result localreview.Result) ([]byte, error) {
	report, err := result.Report()
	if err != nil {
		return nil, err
	}
	log, err := buildModelReviewSARIF(report)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(log)
	if err != nil {
		return nil, fmt.Errorf("encode model review SARIF: %w", err)
	}
	if len(encoded)+1 > maxDiagnosticSARIFBytes {
		return nil, fmt.Errorf("model review SARIF exceeds %d-byte limit", maxDiagnosticSARIFBytes)
	}
	return append(encoded, '\n'), nil
}
