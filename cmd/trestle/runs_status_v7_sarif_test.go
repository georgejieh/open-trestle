package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/review"
)

func finalSARIFSet(t *testing.T, outcome diagnostics.FinalOutcome, withDeterministic, withVerified bool) (diagnostics.Set, diagnostics.DeterministicObservation, diagnostics.Finding) {
	t.Helper()
	_, receipt := remotePlanAndReceipt(t)
	var deterministic, verified diagnostics.Set
	var observation diagnostics.DeterministicObservation
	var finding diagnostics.Finding
	if withDeterministic {
		check, err := diagnostics.NewDeterministicCheck("24b00a4f30827fb105067c28f424b27c8743be48316d4f88326c0153ec7e8f4b", strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckFailed, 1, 1, 1, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		observation, err = diagnostics.NewDeterministicObservation(strings.Repeat("6", 64), strings.Repeat("5", 64), strings.Repeat("8", 64), check.Identity(), "Static observation", "Exact range", diagnostics.SeverityWarning, "static source.go", 2, 3, []string{strings.Repeat("4", 64)})
		if err != nil {
			t.Fatal(err)
		}
		deterministic, err = diagnostics.NewSetWithDeterministicObservations(receipt.Scope(), strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("8", 64), []diagnostics.DeterministicCheck{check}, []diagnostics.DeterministicObservation{observation})
		if err != nil {
			t.Fatal(err)
		}
		if withVerified {
			finding, err = diagnostics.NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Independently verified", "Separate evidence", diagnostics.SeverityError, "verified source.go", 7, 9, []string{strings.Repeat("c", 64)})
			if err != nil {
				t.Fatal(err)
			}
			verified, err = diagnostics.NewSetWithDeterministicChecks(receipt.Scope(), strings.Repeat("9", 64), deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), []diagnostics.Finding{finding})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	snapshot, revision := "", ""
	if withDeterministic {
		snapshot, revision = deterministic.SnapshotIdentity(), deterministic.HeadRevision()
	}
	set, err := diagnostics.NewFinalReviewSet(receipt.Scope(), snapshot, revision, outcome, deterministic, verified)
	if err != nil {
		t.Fatal(err)
	}
	return set, observation, finding
}

func TestV7SARIFSeparatesRecordedAxesAndReportsTerminalOutcome(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		outcome                 diagnostics.FinalOutcome
		deterministic, verified bool
		wantResults             int
	}{
		{"completed_both", diagnostics.FinalOutcomeCompleted, true, true, 2},
		{"abstained_observation_only", diagnostics.FinalOutcomeAbstained, true, false, 1},
		{"failed_no_evidence", diagnostics.FinalOutcomeFailed, false, false, 0},
		{"canceled_no_evidence", diagnostics.FinalOutcomeCanceled, false, false, 0},
		{"inconclusive_no_evidence", diagnostics.FinalOutcomeInconclusive, false, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, obs, finding := finalSARIFSet(t, tc.outcome, tc.deterministic, tc.verified)
			log, err := buildDiagnosticSetSARIF(set)
			if err != nil {
				t.Fatal(err)
			}
			if len(log.Runs) != 1 {
				t.Fatalf("runs: %#v", log)
			}
			run := log.Runs[0]
			if len(run.Results) != tc.wantResults || len(run.Tool.Driver.Rules) != tc.wantResults {
				t.Fatalf("results/rules = %d/%d, want %d", len(run.Results), len(run.Tool.Driver.Rules), tc.wantResults)
			}
			if run.Properties.Status != review.OutcomeInconclusive || string(run.Properties.FinalOutcome) != string(tc.outcome) || !strings.Contains(run.Properties.Reason, string(tc.outcome)) || !strings.Contains(run.Properties.Reason, "no approval") {
				t.Fatalf("outcome properties: %+v", run.Properties)
			}
			if run.Properties.DiagnosticSetID != set.Identity() || run.Properties.SourceSnapshotID != set.SnapshotIdentity() || run.Properties.SnapshotID != "" {
				t.Fatalf("set/source identity: %+v", run.Properties)
			}
			if tc.deterministic {
				result := run.Results[0]
				if result.RuleID != staticDebugOutputSARIFRule || run.Tool.Driver.Rules[0].ID != staticDebugOutputSARIFRule || !reflect.DeepEqual(result.Fingerprints, map[string]string{"openTrestleObservationId/v1": obs.Identity()}) || result.Properties.ObservationIdentity != obs.Identity() || result.Properties.CheckID != set.DeterministicChecks()[0].Identity() || result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "static%20source.go" || result.Locations[0].PhysicalLocation.Region.StartLine != 2 {
					t.Fatalf("observation result: %+v", result)
				}
				if run.Properties.AnalysisResultID != set.AnalysisResultIdentity() || run.Properties.MatchCount == nil || *run.Properties.MatchCount != 1 {
					t.Fatalf("deterministic metadata: %+v", run.Properties)
				}
			} else if run.Properties.CheckID != "" || run.Properties.AnalysisResultID != "" || run.Properties.CandidateCount != nil {
				t.Fatalf("invented evidence metadata: %+v", run.Properties)
			}
			if tc.verified {
				if run.Properties.ReviewSnapshotID != strings.Repeat("9", 64) || run.Properties.ReviewSnapshotID == run.Properties.SourceSnapshotID {
					t.Fatalf("review/source snapshots conflated: %+v", run.Properties)
				}
				result := run.Results[1]
				if result.RuleID != verifiedFindingSARIFRule || run.Tool.Driver.Rules[1].ID != verifiedFindingSARIFRule || !reflect.DeepEqual(result.Fingerprints, map[string]string{"openTrestleVerifiedFindingId/v1": finding.Identity(), "openTrestleFindingFingerprint/v1": finding.Fingerprint()}) || result.Properties.ObservationIdentity != "" || result.Properties.CheckID != "" || result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "verified%20source.go" || result.Locations[0].PhysicalLocation.Region.StartLine != 7 || run.Properties.VerifiedCount == nil || *run.Properties.VerifiedCount != 1 {
					t.Fatalf("finding result/metadata: %+v %+v", result, run.Properties)
				}
			} else if run.Properties.VerifiedSetID != "" || run.Properties.VerifiedCount != nil || run.Properties.ReviewSnapshotID != "" {
				t.Fatalf("invented verification metadata: %+v", run.Properties)
			}
		})
	}
}

func TestV7RunStatusJSONReturnsCanonicalStandaloneSet(t *testing.T) {
	_, receipt := remotePlanAndReceipt(t)
	set, _, _ := finalSARIFSet(t, diagnostics.FinalOutcomeAbstained, true, false)
	encodedSet, err := diagnostics.EncodeSet(set)
	if err != nil {
		t.Fatal(err)
	}
	encodedReceipt, err := controlplane.EncodeReviewRunReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	runResponse, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-run", "run": json.RawMessage(encodedReceipt)})
	diagnosticResponse, _ := json.Marshal(map[string]any{"contract": "open-trestle/api-response", "schema_version": 1, "request_id": "request-diagnostics", "diagnostics": json.RawMessage(encodedSet)})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
			t.Errorf("unauthorized: %s", r.URL)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a":
			_, _ = w.Write(runResponse)
		case "/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/diagnostics":
			_, _ = w.Write(diagnosticResponse)
		default:
			t.Errorf("unexpected path: %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
	var out, errs bytes.Buffer
	exit := run([]string{"runs", "status", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a", "--server", server.URL, "--format", "json"}, &out, &errs)
	if exit != 0 || errs.Len() != 0 || !bytes.Equal(out.Bytes(), append(encodedSet, '\n')) {
		t.Fatalf("exit=%d stdout=%s stderr=%s", exit, out.String(), errs.String())
	}
}
