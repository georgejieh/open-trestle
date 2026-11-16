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

func TestBuildV1DiagnosticSetSARIFIsAdvisoryWithoutInventedCoverage(t *testing.T) {
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-v1-sarif")
	if err != nil {
		t.Fatal(err)
	}
	finding, err := diagnostics.NewFinding(
		strings.Repeat("a", 64), strings.Repeat("b", 64), "Verified issue",
		"Independent evidence confirms the range.", diagnostics.SeverityError,
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
		name     string
		findings []diagnostics.Finding
	}{
		{name: "verified_finding", findings: []diagnostics.Finding{finding}},
		{name: "zero_findings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := diagnostics.NewSet(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), tc.findings)
			if err != nil {
				t.Fatalf("NewSet: %v", err)
			}
			if set.SchemaVersion() != 1 {
				t.Fatalf("schema version = %d, want 1", set.SchemaVersion())
			}
			if err := set.Validate(); err != nil {
				t.Fatalf("canonical set validation: %v", err)
			}
			canonical := set.Findings()
			log, err := buildDiagnosticSetSARIF(set)
			if err != nil {
				t.Fatalf("buildDiagnosticSetSARIF(valid v1 set): %v", err)
			}
			if log.Schema != sarifSchemaURI || log.Version != "2.1.0" || len(log.Runs) != 1 {
				t.Fatalf("SARIF header/runs = (%q, %q, %d)", log.Schema, log.Version, len(log.Runs))
			}
			run := log.Runs[0]
			if run.Tool.Driver.Name != "Open Trestle" || len(run.Results) != len(canonical) {
				t.Fatalf("driver/results = (%#v, %#v), want %d verified findings", run.Tool.Driver, run.Results, len(canonical))
			}
			if len(run.Tool.Driver.Rules) != len(canonical) {
				t.Fatalf("rules = %#v, want one verified-finding rule only if a finding exists", run.Tool.Driver.Rules)
			}
			if len(canonical) != 0 {
				rule := run.Tool.Driver.Rules[0]
				if rule.ID != verifiedFindingSARIFRule || rule.ShortDescription.Text != "Independently verified finding" || rule.DefaultConfiguration.Level != "warning" {
					t.Fatalf("verified rule = %#v", rule)
				}
			}
			if run.Properties.Status != review.OutcomeInconclusive || !strings.HasPrefix(run.Properties.Reason, "review status is advisory; no approval asserted") || !strings.Contains(run.Properties.Reason, "source coverage unavailable") || !strings.Contains(run.Properties.Reason, "candidate") {
				t.Fatalf("v1 status/reason must be advisory and qualify missing coverage: %#v", run.Properties)
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
				"trestleVerifiedSetId": set.VerifiedSetIdentity(),
			}
			if !reflect.DeepEqual(props, wantProps) {
				t.Fatalf("run properties = %#v, want only recorded v1 identities/status %#v", props, wantProps)
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
					t.Fatalf("result %d = %#v, want only actual verified finding %#v", i, actual, want)
				}
				if actual.Fingerprints["openTrestleVerifiedFindingId/v1"] == expected.SourceIdentity() {
					t.Fatal("diagnostic identity unexpectedly equals original source identity")
				}
			}
		})
	}
}
