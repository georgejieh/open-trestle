package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/review"
)

func TestBuildV4DiagnosticSetSARIFExportsOnlyRecordedOmissions(t *testing.T) {
	authorization, err := diagnostics.NewOmissionSummary(diagnostics.OmissionAuthorization, 1)
	if err != nil {
		t.Fatalf("NewOmissionSummary(authorization): %v", err)
	}
	selectionLimit, err := diagnostics.NewOmissionSummary(diagnostics.OmissionSelectionLimit, 1)
	if err != nil {
		t.Fatalf("NewOmissionSummary(selection_limit): %v", err)
	}

	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-v4-sarif")
	if err != nil {
		t.Fatal(err)
	}
	finding, err := diagnostics.NewFinding(
		strings.Repeat("a", 64), strings.Repeat("b", 64), "Verified issue",
		"Independent evidence confirms the range.", diagnostics.SeverityWarning,
		"internal/review source.go", 4, 6,
		[]string{strings.Repeat("c", 64), strings.Repeat("9", 64)},
	)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	if err := finding.Validate(); err != nil {
		t.Fatalf("finding validation: %v", err)
	}

	for _, tc := range []struct {
		name                               string
		findings                           []diagnostics.Finding
		candidates, rejected, inconclusive uint16
		analyzed, selected, omitted        uint32
		omissions                          []diagnostics.OmissionSummary
	}{
		{name: "verified_with_mixed_candidates_and_two_omissions", findings: []diagnostics.Finding{finding}, candidates: 4, rejected: 2, inconclusive: 1, analyzed: 4, selected: 2, omitted: 2, omissions: []diagnostics.OmissionSummary{selectionLimit, authorization}},
		{name: "zero_findings_zero_candidates_full_selection", analyzed: 1, selected: 1},
		{name: "rejected_without_finding_full_selection", candidates: 1, rejected: 1, analyzed: 1, selected: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := diagnostics.NewSetWithOmissionReasons(scope, strings.Repeat("d", 64),
				strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64),
				tc.candidates, tc.rejected, tc.inconclusive, tc.analyzed, tc.selected, tc.omitted, tc.omissions, tc.findings)
			if err != nil {
				t.Fatalf("NewSetWithOmissionReasons: %v", err)
			}
			if set.SchemaVersion() != 4 {
				t.Fatalf("schema version = %d, want 4", set.SchemaVersion())
			}
			if err := set.Validate(); err != nil {
				t.Fatalf("canonical set validation: %v", err)
			}
			canonical := set.Findings()
			canonicalOmissions := set.OmissionSummaries()
			if tc.omitted > 0 && (len(canonicalOmissions) != 2 || canonicalOmissions[0].Reason() != diagnostics.OmissionAuthorization || canonicalOmissions[1].Reason() != diagnostics.OmissionSelectionLimit) {
				t.Fatalf("constructor did not canonically sort unsorted reasons: %#v", canonicalOmissions)
			}
			log, err := buildDiagnosticSetSARIF(set)
			if err != nil {
				t.Fatalf("buildDiagnosticSetSARIF(valid v4 set): %v", err)
			}
			if log.Schema != sarifSchemaURI || log.Version != "2.1.0" || len(log.Runs) != 1 {
				t.Fatalf("SARIF header/runs = (%q, %q, %d)", log.Schema, log.Version, len(log.Runs))
			}
			run := log.Runs[0]
			if run.Tool.Driver.Name != "Open Trestle" || len(run.Results) != len(canonical) {
				t.Fatalf("driver/results = (%#v, %#v), want %d recorded findings", run.Tool.Driver, run.Results, len(canonical))
			}
			if len(run.Tool.Driver.Rules) != len(canonical) {
				t.Fatalf("rules = %#v, want a verified-finding rule only for recorded findings", run.Tool.Driver.Rules)
			}
			if len(canonical) > 0 {
				rule := run.Tool.Driver.Rules[0]
				if rule.ID != verifiedFindingSARIFRule || rule.ShortDescription.Text != "Independently verified finding" || rule.DefaultConfiguration.Level != "warning" {
					t.Fatalf("verified finding rule = %#v", rule)
				}
			}
			reason := run.Properties.Reason
			if run.Properties.Status != review.OutcomeInconclusive ||
				!strings.HasPrefix(reason, "review status is advisory; no approval asserted") ||
				strings.Contains(strings.ToLower(reason), "whole-repo") ||
				strings.Contains(strings.ToLower(reason), "whole repository") ||
				strings.Contains(strings.ToLower(reason), "cleared") ||
				strings.Contains(strings.ToLower(reason), "coverage complete") {
				t.Fatalf("v4 reason must remain advisory without whole-repo clearance: %q", reason)
			}
			if (tc.inconclusive > 0) != strings.Contains(reason, "candidate verification inconclusive") ||
				(tc.rejected > 0) != strings.Contains(reason, "rejected candidates") ||
				strings.Contains(reason, "omission reasons unavailable") ||
				(tc.omitted > 0) != (strings.Contains(reason, "source omission") || strings.Contains(reason, "source selection partial")) {
				t.Fatalf("v4 reason must qualify only actual unresolved accounting: %q", reason)
			}
			encoded, err := json.Marshal(run.Properties)
			if err != nil {
				t.Fatal(err)
			}
			var props map[string]any
			if err := json.Unmarshal(encoded, &props); err != nil {
				t.Fatal(err)
			}
			delete(props, "trestleReason")
			wantProps := map[string]any{
				"trestleStatus": "inconclusive", "trestleDiagnosticSetId": set.Identity(),
				"trestleSnapshotId": set.SnapshotIdentity(), "trestleRevision": set.HeadRevision(),
				"trestleVerifiedSetId":         set.VerifiedSetIdentity(),
				"trestleVerificationContextId": set.VerificationContextIdentity(),
				"trestleCandidateCount":        float64(tc.candidates), "trestleVerifiedCount": float64(len(canonical)),
				"trestleRejectedCount": float64(tc.rejected), "trestleInconclusiveCount": float64(tc.inconclusive),
				"trestleSourceAnalyzedCount": float64(tc.analyzed), "trestleSourceSelectedCount": float64(tc.selected),
				"trestleSourceOmittedCount": float64(tc.omitted),
			}
			if tc.omitted > 0 {
				wantProps["trestleOmissions"] = []any{
					map[string]any{"reason": "authorization", "count": float64(1)},
					map[string]any{"reason": "selection_limit", "count": float64(1)},
				}
			}
			if !reflect.DeepEqual(props, wantProps) {
				t.Fatalf("serialized run properties = %#v, want only recorded v4 fields %#v", props, wantProps)
			}
			if len(run.Properties.Omissions) != len(canonicalOmissions) {
				t.Fatalf("run omissions = %#v, want %d canonical aggregates", run.Properties.Omissions, len(canonicalOmissions))
			}
			for i, omission := range run.Properties.Omissions {
				if omission.Reason != canonicalOmissions[i].Reason().String() || omission.Count != canonicalOmissions[i].Count() {
					t.Fatalf("omission %d = %#v, want canonical summary %#v", i, omission, canonicalOmissions[i])
				}
			}
			for i, actual := range run.Results {
				expected := canonical[i]
				level, err := diagnosticSARIFLevel(expected.Severity())
				if err != nil {
					t.Fatal(err)
				}
				want := sarifResult{
					RuleID: verifiedFindingSARIFRule, Level: level,
					Message: sarifMessage{Text: expected.Title() + ": " + expected.Message()},
					Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(expected.Path())},
						Region:           sarifRegion{StartLine: int(expected.StartLine()), EndLine: int(expected.EndLine())},
					}}},
					Fingerprints: map[string]string{
						"openTrestleVerifiedFindingId/v1":  expected.Identity(),
						"openTrestleFindingFingerprint/v1": expected.Fingerprint(),
					},
					Properties: sarifResultProperties{EvidenceIDs: expected.EvidenceIDs()},
				}
				if !reflect.DeepEqual(actual, want) {
					t.Fatalf("result %d = %#v, want only recorded finding %#v", i, actual, want)
				}
				if actual.Fingerprints["openTrestleVerifiedFindingId/v1"] == expected.SourceIdentity() {
					t.Fatal("result diagnostic identity unexpectedly equals original source identity")
				}
			}
		})
	}
}
