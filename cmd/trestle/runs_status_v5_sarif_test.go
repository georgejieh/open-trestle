package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
)

func TestRunStatusV5SARIFPreservesVerificationAndSelectionCoverage(t *testing.T) {
	_, receipt := remotePlanAndReceipt(t)
	passedCheck, err := diagnostics.NewDeterministicCheck(
		"3f01f93e51003eb3a0deca04719a3957d6e367c97c33bdfea105174d95698092",
		strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckPassed, 1, 2, 1, 2, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	// This public source-check identity describes one failed exact match; v5 has no observation record.
	failedCheck, err := diagnostics.NewDeterministicCheck(
		"24b00a4f30827fb105067c28f424b27c8743be48316d4f88326c0153ec7e8f4b",
		strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckFailed, 1, 1, 1, 1, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	omission, err := diagnostics.NewOmissionSummary(diagnostics.OmissionSelectionLimit, 1)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := diagnostics.NewFinding(
		strings.Repeat("a", 64), strings.Repeat("b", 64), "Verified issue",
		"Independent evidence confirms the changed range.", diagnostics.SeverityWarning,
		"internal/review source.go", 4, 6, []string{strings.Repeat("c", 64), strings.Repeat("9", 64)},
	)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name                     string
		candidates, inconclusive uint16
		check                    diagnostics.DeterministicCheck
		findings                 []diagnostics.Finding
	}{
		{name: "no_verified_findings", candidates: 1, inconclusive: 1, check: passedCheck},
		{name: "verified_finding_with_inconclusive_candidate", candidates: 2, inconclusive: 1, check: passedCheck, findings: []diagnostics.Finding{finding}},
		{name: "failed_check_match_without_observation", candidates: 1, inconclusive: 1, check: failedCheck},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, err := diagnostics.NewSetWithDeterministicChecks(
				receipt.Scope(), strings.Repeat("d", 64), strings.Repeat("1", 40),
				strings.Repeat("e", 64), strings.Repeat("f", 64),
				tc.candidates, 0, tc.inconclusive, 2, 1, 1,
				[]diagnostics.OmissionSummary{omission}, []diagnostics.DeterministicCheck{tc.check}, tc.findings,
			)
			if err != nil || set.Validate() != nil || set.SchemaVersion() != 5 {
				t.Fatalf("invalid canonical v5 fixture: %v", err)
			}
			encodedSet, err := diagnostics.EncodeSet(set)
			if err != nil {
				t.Fatal(err)
			}
			encodedReceipt, err := controlplane.EncodeReviewRunReceipt(receipt)
			if err != nil {
				t.Fatal(err)
			}
			runResponse, err := json.Marshal(map[string]any{
				"contract": "open-trestle/api-response", "schema_version": 1,
				"request_id": "request-run", "run": json.RawMessage(encodedReceipt),
			})
			if err != nil {
				t.Fatal(err)
			}
			diagnosticResponse, err := json.Marshal(map[string]any{
				"contract": "open-trestle/api-response", "schema_version": 1,
				"request_id": "request-diagnostics", "diagnostics": json.RawMessage(encodedSet),
			})
			if err != nil {
				t.Fatal(err)
			}
			runPath := "/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a"
			gotPaths := make([]string, 0, 4)
			var pathsMu sync.Mutex
			snapshotPaths := func() []string {
				pathsMu.Lock()
				defer pathsMu.Unlock()
				return append([]string(nil), gotPaths...)
			}
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				pathsMu.Lock()
				gotPaths = append(gotPaths, request.Method+" "+request.URL.RequestURI())
				pathsMu.Unlock()
				if request.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
					t.Errorf("bad bearer token on %s", request.URL.Path)
					http.Error(writer, "unauthorized", http.StatusUnauthorized)
					return
				}
				writer.Header().Set("Content-Type", "application/json")
				switch {
				case request.Method == http.MethodGet && request.URL.RequestURI() == runPath:
					_, _ = writer.Write(runResponse)
				case request.Method == http.MethodGet && request.URL.RequestURI() == runPath+"/diagnostics":
					_, _ = writer.Write(diagnosticResponse)
				default:
					t.Errorf("unexpected scoped request: %s %s", request.Method, request.URL.RequestURI())
					http.NotFound(writer, request)
				}
			}))
			defer server.Close()
			t.Setenv("OPEN_TRESTLE_API_TOKEN", "01234567890123456789012345678901")
			base := []string{"runs", "status", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a", "--server", server.URL}
			var jsonOut, jsonErr bytes.Buffer
			if exit := run(append(append([]string(nil), base...), "--format", "json"), &jsonOut, &jsonErr); exit != 0 || jsonErr.Len() != 0 || !bytes.Equal(jsonOut.Bytes(), append(append([]byte(nil), encodedSet...), '\n')) {
				t.Fatalf("JSON control: exit=%d stdout=%q stderr=%q", exit, jsonOut.String(), jsonErr.String())
			}
			jsonPaths := []string{"GET " + runPath, "GET " + runPath + "/diagnostics"}
			if paths := snapshotPaths(); !reflect.DeepEqual(paths, jsonPaths) {
				t.Fatalf("JSON scoped requests=%v, want %v", paths, jsonPaths)
			}
			var sarifOut, sarifErr bytes.Buffer
			if exit := run(append(append([]string(nil), base...), "--format", "sarif"), &sarifOut, &sarifErr); exit != 0 || sarifErr.Len() != 0 {
				t.Fatalf("v5 SARIF: exit=%d stdout=%q stderr=%q", exit, sarifOut.String(), sarifErr.String())
			}
			wantPaths := []string{"GET " + runPath, "GET " + runPath + "/diagnostics", "GET " + runPath, "GET " + runPath + "/diagnostics"}
			if paths := snapshotPaths(); !reflect.DeepEqual(paths, wantPaths) {
				t.Fatalf("scoped requests=%v, want %v", paths, wantPaths)
			}
			if len(sarifOut.Bytes()) == 0 || sarifOut.Bytes()[len(sarifOut.Bytes())-1] != '\n' {
				t.Fatalf("SARIF missing newline: %q", sarifOut.String())
			}
			var log struct {
				Schema  string `json:"$schema"`
				Version string `json:"version"`
				Runs    []struct {
					Tool struct {
						Driver struct {
							Rules []struct {
								ID string `json:"id"`
							} `json:"rules"`
						} `json:"driver"`
					} `json:"tool"`
					Results []struct {
						RuleID  string `json:"ruleId"`
						Level   string `json:"level"`
						Message struct {
							Text string `json:"text"`
						} `json:"message"`
						Locations []struct {
							PhysicalLocation struct {
								ArtifactLocation struct {
									URI string `json:"uri"`
								} `json:"artifactLocation"`
								Region struct {
									StartLine int `json:"startLine"`
									EndLine   int `json:"endLine"`
								} `json:"region"`
							} `json:"physicalLocation"`
						} `json:"locations"`
						Fingerprints map[string]string `json:"fingerprints"`
						Properties   map[string]any    `json:"properties"`
					} `json:"results"`
					Properties map[string]any `json:"properties"`
				} `json:"runs"`
			}
			if err := json.Unmarshal(sarifOut.Bytes(), &log); err != nil {
				t.Fatalf("invalid SARIF JSON: %v", err)
			}
			if log.Schema != sarifSchemaURI || log.Version != "2.1.0" || len(log.Runs) != 1 {
				t.Fatalf("SARIF header/runs: %#v", log)
			}
			sarifRun := log.Runs[0]
			if len(sarifRun.Results) != len(tc.findings) {
				t.Fatalf("results=%d, want %d", len(sarifRun.Results), len(tc.findings))
			}
			properties := sarifRun.Properties
			for key, want := range map[string]any{
				"trestleStatus": "inconclusive", "trestleDiagnosticSetId": set.Identity(),
				"trestleSnapshotId": set.SnapshotIdentity(), "trestleRevision": set.HeadRevision(),
				"trestleVerifiedSetId": set.VerifiedSetIdentity(), "trestleVerificationContextId": set.VerificationContextIdentity(),
				"trestleCheckId": tc.check.Identity(), "trestleCheckState": tc.check.State().String(),
				"trestleSourceCheckId": tc.check.SourceCheckIdentity(), "trestleCheckAnalysisResultId": tc.check.AnalysisResultIdentity(),
				"trestleChangeId": tc.check.ChangeIdentity(), "trestleCheckKey": tc.check.Key(),
				"trestleCheckRuleVersion": float64(tc.check.RuleVersion()),
				"trestleApplicableFiles":  float64(tc.check.ApplicableFiles()), "trestleApplicableRanges": float64(tc.check.ApplicableRanges()),
				"trestleCheckedFiles": float64(tc.check.CheckedFiles()), "trestleCheckedRanges": float64(tc.check.CheckedRanges()),
				"trestleMatchCount":     float64(tc.check.MatchCount()),
				"trestleCandidateCount": float64(tc.candidates), "trestleVerifiedCount": float64(len(tc.findings)),
				"trestleRejectedCount": float64(0), "trestleInconclusiveCount": float64(tc.inconclusive),
				"trestleSourceAnalyzedCount": float64(2), "trestleSourceSelectedCount": float64(1), "trestleSourceOmittedCount": float64(1),
			} {
				if !reflect.DeepEqual(properties[key], want) {
					t.Errorf("run property %s=%v, want %v", key, properties[key], want)
				}
			}
			if properties["trestleAnalysisResultId"] != nil && properties["trestleAnalysisResultId"] != "" {
				t.Errorf("v5 set-level analysis result must remain empty: %v", properties["trestleAnalysisResultId"])
			}
			reason, _ := properties["trestleReason"].(string)
			if !strings.Contains(reason, "inconclusive") || !(strings.Contains(reason, "omission") || strings.Contains(reason, "omitted")) {
				t.Errorf("incomplete coverage reason=%q", reason)
			}
			if tc.check.State() == diagnostics.CheckFailed && !strings.Contains(reason, "failed") {
				t.Errorf("failed check missing from conservative reason=%q", reason)
			}
			wantOmissions := []any{map[string]any{"reason": "selection_limit", "count": float64(1)}}
			if !reflect.DeepEqual(properties["trestleOmissions"], wantOmissions) {
				t.Errorf("omissions=%v, want %v", properties["trestleOmissions"], wantOmissions)
			}
			if len(tc.findings) == 0 {
				// A stable verified-finding catalogue is allowed; no static rule or result is invented.
				if len(sarifRun.Tool.Driver.Rules) > 1 || len(sarifRun.Tool.Driver.Rules) == 1 && sarifRun.Tool.Driver.Rules[0].ID != "open-trestle-verified-finding" {
					t.Errorf("zero-findings rules=%v", sarifRun.Tool.Driver.Rules)
				}
				return
			}
			if len(sarifRun.Tool.Driver.Rules) != 1 || sarifRun.Tool.Driver.Rules[0].ID != "open-trestle-verified-finding" {
				t.Errorf("verified rule catalogue=%v", sarifRun.Tool.Driver.Rules)
			}
			result := sarifRun.Results[0]
			if result.RuleID != "open-trestle-verified-finding" || result.Level != "warning" || result.Message.Text != finding.Title()+": "+finding.Message() {
				t.Errorf("verified result metadata=%+v", result)
			}
			if len(result.Locations) != 1 || result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "internal/review%20source.go" || result.Locations[0].PhysicalLocation.Region.StartLine != 4 || result.Locations[0].PhysicalLocation.Region.EndLine != 6 {
				t.Errorf("verified range=%v", result.Locations)
			}
			if result.Fingerprints["openTrestleVerifiedFindingId/v1"] != finding.Identity() || result.Fingerprints["openTrestleFindingFingerprint/v1"] != finding.Fingerprint() {
				t.Errorf("verified fingerprints=%v", result.Fingerprints)
			}
			wantEvidence := []any{strings.Repeat("9", 64), strings.Repeat("c", 64)}
			if !reflect.DeepEqual(result.Properties["trestleEvidenceIds"], wantEvidence) {
				t.Errorf("verified evidence=%v, want %v", result.Properties["trestleEvidenceIds"], wantEvidence)
			}
			if result.Properties["trestleCheckId"] != nil || result.Properties["trestleObservationId"] != nil {
				t.Errorf("finding confused with static observation: %v", result.Properties)
			}
		})
	}
}
