package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/diagnostics"
)

func TestRunLSPAuthenticatedStoredAndExportedDiagnosticJourney(t *testing.T) {
	plan, _ := remotePlanAndReceipt(t)
	finding, err := diagnostics.NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64),
		"DEVELOPMENT fixture finding", "Synthetic transport evidence, not a host review.",
		diagnostics.SeverityWarning, "internal/review source.go", 4, 6, []string{strings.Repeat("c", 64), strings.Repeat("9", 64)})
	if err != nil {
		t.Fatal(err)
	}
	omission, err := diagnostics.NewOmissionSummary(diagnostics.OmissionSelectionLimit, 1)
	if err != nil {
		t.Fatal(err)
	}
	verifiedCheck, err := diagnostics.NewDeterministicCheck("3f01f93e51003eb3a0deca04719a3957d6e367c97c33bdfea105174d95698092", strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckPassed, 1, 2, 1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := diagnostics.NewSetWithDeterministicChecks(plan.Scope(), strings.Repeat("d", 64),
		strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64),
		1, 0, 0, 2, 1, 1, []diagnostics.OmissionSummary{omission}, []diagnostics.DeterministicCheck{verifiedCheck}, []diagnostics.Finding{finding})
	if err != nil {
		t.Fatal(err)
	}
	analysisID := strings.Repeat("8", 64)
	check, err := diagnostics.NewDeterministicCheck("24b00a4f30827fb105067c28f424b27c8743be48316d4f88326c0153ec7e8f4b",
		analysisID, strings.Repeat("7", 64), diagnostics.CheckFailed, 1, 1, 1, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := diagnostics.NewDeterministicObservation(strings.Repeat("6", 64), strings.Repeat("5", 64),
		analysisID, check.Identity(), "DEVELOPMENT fixture observation", "Synthetic rule match, not independent verification.",
		diagnostics.SeverityWarning, finding.Path(), finding.StartLine(), finding.EndLine(), finding.EvidenceIDs())
	if err != nil {
		t.Fatal(err)
	}
	deterministic, err := diagnostics.NewSetWithDeterministicObservations(plan.Scope(), verified.SnapshotIdentity(),
		verified.HeadRevision(), analysisID, []diagnostics.DeterministicCheck{check}, []diagnostics.DeterministicObservation{observation})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		set  diagnostics.Set
	}{
		{"verified_finding_with_omitted_source", verified},
		{"deterministic_observation_is_not_an_editor_finding", deterministic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.Open(ctx, plan, time.UnixMilli(100)); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(t.TempDir(), "diagnostics")
			writer, err := diagnostics.NewFileStore(root)
			if err != nil {
				t.Fatal(err)
			}
			if inserted, err := writer.PutDiagnosticSet(ctx, tc.set); err != nil || !inserted {
				t.Fatalf("persist diagnostic set: inserted=%t err=%v", inserted, err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			store, err := diagnostics.NewFileStore(root)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			const token = "01234567890123456789012345678901"
			principal, err := httpapi.NewPrincipal("development-observer", "tenant-a", []string{"repo-a"}, []httpapi.Capability{httpapi.CapabilityRunRead})
			if err != nil {
				t.Fatal(err)
			}
			auth, err := httpapi.NewStaticTokenAuthenticator([]httpapi.StaticToken{{Token: token, Principal: principal}})
			if err != nil {
				t.Fatal(err)
			}
			handler, err := httpapi.NewServerWithDiagnostics(coordinator, auth, httpapi.SystemClock{}, store)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(handler)
			defer server.Close()
			t.Setenv("OPEN_TRESTLE_API_TOKEN", token)
			args := []string{"runs", "status", "--tenant", "tenant-a", "--repository", "repo-a", "--run", "run-a", "--server", server.URL}
			var exported, stderr bytes.Buffer
			if code := run(append(append([]string{}, args...), "--format", "json"), &exported, &stderr); code != 0 || stderr.Len() != 0 {
				t.Fatalf("JSON export: exit=%d stderr=%s", code, &stderr)
			}
			canonical, err := diagnostics.EncodeSet(tc.set)
			if err != nil || !bytes.Equal(exported.Bytes(), append(canonical, '\n')) {
				t.Fatalf("stored diagnostic export changed canonical bytes: %v", err)
			}
			exportedSet, err := diagnostics.ParseSet(bytes.TrimSpace(exported.Bytes()))
			if err != nil || !reflect.DeepEqual(exportedSet.OmissionSummaries(), tc.set.OmissionSummaries()) || exportedSet.SourceOmittedCount() != tc.set.SourceOmittedCount() {
				t.Fatalf("export lost omission evidence: %v", err)
			}
			var sarifOutput bytes.Buffer
			if code := run(append(append([]string{}, args...), "--format", "sarif"), &sarifOutput, &stderr); code != 0 || stderr.Len() != 0 {
				t.Fatalf("SARIF export: exit=%d stderr=%s", code, &stderr)
			}
			var log sarifLog
			if err := json.Unmarshal(sarifOutput.Bytes(), &log); err != nil || len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 {
				t.Fatalf("SARIF response: %s %v", &sarifOutput, err)
			}
			sarifRun := log.Runs[0]
			if sarifRun.Properties.DiagnosticSetID != tc.set.Identity() || sarifRun.Properties.Status != "inconclusive" || !reflect.DeepEqual(sarifRun.Results[0].Properties.EvidenceIDs, finding.EvidenceIDs()) {
				t.Fatalf("SARIF evidence or disposition changed: %+v", sarifRun)
			}
			if tc.set.SchemaVersion() == 4 {
				if sarifRun.Properties.SourceOmittedCount == nil || *sarifRun.Properties.SourceOmittedCount != tc.set.SourceOmittedCount() || !reflect.DeepEqual(sarifRun.Properties.Omissions, []sarifOmission{{Reason: omission.Reason().String(), Count: omission.Count()}}) || sarifRun.Results[0].Fingerprints["openTrestleVerifiedFindingId/v1"] != finding.Identity() {
					t.Fatalf("SARIF omitted-source/finding evidence changed: %+v", sarifRun)
				}
			} else if sarifRun.Results[0].Properties.ObservationIdentity != observation.Identity() || sarifRun.Properties.CheckID != check.Identity() {
				t.Fatalf("SARIF observation authority changed: %+v", sarifRun)
			}
			path := filepath.Join(t.TempDir(), "exported-diagnostics.json")
			if err := os.WriteFile(path, exported.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			for name, invalid := range map[string][]byte{
				"extra_line_feed":           append(append([]byte{}, exported.Bytes()...), '\n'),
				"second_record":             append(append([]byte{}, exported.Bytes()...), exported.Bytes()...),
				"trailing_bytes":            append(append([]byte{}, exported.Bytes()...), 'x'),
				"carriage_return_line_feed": append(append([]byte{}, canonical...), '\r', '\n'),
				"interior_whitespace":       bytes.Replace(canonical, []byte("{\"contract\":"), []byte("{ \"contract\":"), 1),
				"unknown_field":             append(append([]byte{}, canonical[:len(canonical)-1]...), []byte(",\"unexpected\":true}\n")...),
			} {
				t.Run("reject_"+name, func(t *testing.T) {
					invalidPath := filepath.Join(t.TempDir(), "invalid-diagnostics.json")
					if err := os.WriteFile(invalidPath, invalid, 0o600); err != nil {
						t.Fatal(err)
					}
					var output, errors bytes.Buffer
					if code := runLSP([]string{"--diagnostics", invalidPath}, strings.NewReader(""), &output, &errors); code != 1 || output.Len() != 0 || errors.Len() == 0 {
						t.Fatalf("invalid offline framing accepted: exit=%d stdout=%s stderr=%s", code, &output, &errors)
					}
				})
			}
			for _, mode := range []struct {
				name string
				args []string
			}{{"authenticated", []string{"--server", server.URL}}, {"exported", []string{"--diagnostics", path}}} {
				t.Run(mode.name, func(t *testing.T) {
					var input bytes.Buffer
					for _, message := range []any{
						map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"rootUri": "file:///workspace", "initializationOptions": map[string]any{"tenant_id": "tenant-a", "repository_id": "repo-a", "review_run_id": "run-a"}}},
						map[string]any{"jsonrpc": "2.0", "id": 2, "method": "textDocument/diagnostic", "params": map[string]any{"textDocument": map[string]any{"uri": "file:///workspace/internal/review%20source.go"}}},
						map[string]any{"jsonrpc": "2.0", "id": 3, "method": "textDocument/diagnostic", "params": map[string]any{"textDocument": map[string]any{"uri": "file:///workspace/internal/review%20source.go"}, "previousResultId": tc.set.Identity()}},
						map[string]any{"jsonrpc": "2.0", "method": "exit"},
					} {
						body, err := json.Marshal(message)
						if err != nil {
							t.Fatal(err)
						}
						fmt.Fprintf(&input, "Content-Length: %d\r\n\r\n%s", len(body), body)
					}
					var output, errors bytes.Buffer
					if code := runLSP(mode.args, &input, &output, &errors); code != 0 || errors.Len() != 0 {
						t.Fatalf("LSP: exit=%d stderr=%s", code, &errors)
					}
					reader := bufio.NewReader(&output)
					for id := 1; id <= 3; id++ {
						header, err := reader.ReadString('\n')
						var length int
						if _, scanErr := fmt.Sscanf(header, "Content-Length: %d\r\n", &length); err != nil || scanErr != nil || length <= 0 || length > 1<<20 {
							t.Fatalf("invalid LSP header %q: %v %v", header, err, scanErr)
						}
						if separator, err := reader.ReadString('\n'); err != nil || separator != "\r\n" {
							t.Fatalf("invalid LSP separator %q: %v", separator, err)
						}
						body := make([]byte, length)
						if _, err := io.ReadFull(reader, body); err != nil {
							t.Fatal(err)
						}
						var response struct {
							ID     int             `json:"id"`
							Error  json.RawMessage `json:"error"`
							Result struct {
								Kind     string `json:"kind"`
								ResultID string `json:"resultId"`
								Items    []struct {
									Code  string `json:"code"`
									Range struct {
										Start, End struct {
											Line uint32 `json:"line"`
										}
									} `json:"range"`
									Data struct {
										DiagnosticIdentity string   `json:"diagnostic_identity"`
										SourceIdentity     string   `json:"source_identity"`
										EvidenceIDs        []string `json:"evidence_ids"`
										SetIdentity        string   `json:"diagnostic_set_identity"`
										SnapshotIdentity   string   `json:"snapshot_identity"`
										HeadRevision       string   `json:"head_revision"`
									} `json:"data"`
								} `json:"items"`
							} `json:"result"`
						}
						if err := json.Unmarshal(body, &response); err != nil || response.ID != id || len(response.Error) != 0 {
							t.Fatalf("LSP response: %s %v", body, err)
						}
						if id == 1 {
							continue
						}
						if response.Result.ResultID != tc.set.Identity() {
							t.Fatalf("editor result identity lost finding and omission binding: %s", body)
						}
						if id == 3 {
							if response.Result.Kind != "unchanged" || response.Result.Items != nil {
								t.Fatalf("unchanged pull: %s", body)
							}
							continue
						}
						if response.Result.Kind != "full" || len(response.Result.Items) != len(tc.set.Findings()) {
							t.Fatalf("editor promoted or lost findings: %s", body)
						}
						if len(tc.set.Findings()) == 0 {
							continue
						}
						item := response.Result.Items[0]
						if item.Code != finding.Fingerprint() || item.Range.Start.Line != finding.StartLine()-1 || item.Range.End.Line != finding.EndLine() || item.Data.DiagnosticIdentity != finding.Identity() || item.Data.SourceIdentity != finding.SourceIdentity() || !reflect.DeepEqual(item.Data.EvidenceIDs, finding.EvidenceIDs()) || item.Data.SetIdentity != tc.set.Identity() || item.Data.SnapshotIdentity != tc.set.SnapshotIdentity() || item.Data.HeadRevision != tc.set.HeadRevision() {
							t.Fatalf("editor finding/range/evidence changed: %s", body)
						}
					}
					if _, err := reader.ReadByte(); err != io.EOF {
						t.Fatalf("unexpected LSP output: %v", err)
					}
				})
			}
		})
	}
}
