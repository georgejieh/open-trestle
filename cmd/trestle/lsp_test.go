package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRunLSPServesStaticVerifiedDiagnostics(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	omission, _ := diagnostics.NewOmissionSummary(diagnostics.OmissionSelectionLimit, 1)
	check, _ := diagnostics.NewDeterministicCheck("3f01f93e51003eb3a0deca04719a3957d6e367c97c33bdfea105174d95698092", strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckPassed, 1, 2, 1, 2, 0)
	set, _ := diagnostics.NewSetWithDeterministicChecks(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64), 0, 0, 0, 2, 1, 1, []diagnostics.OmissionSummary{omission}, []diagnostics.DeterministicCheck{check}, nil)
	encoded, _ := diagnostics.EncodeSet(set)
	path := filepath.Join(t.TempDir(), "diagnostics.json")
	_ = os.WriteFile(path, encoded, 0o600)
	requestBody, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"rootUri": "file:///workspace", "initializationOptions": map[string]any{"tenant_id": "tenant-a", "repository_id": "repo-a", "review_run_id": "run-a"}}})
	input := []byte(fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(requestBody), requestBody))
	var stdout, stderr bytes.Buffer
	if exit := runLSP([]string{"--diagnostics", path}, bytes.NewReader(input), &stdout, &stderr); exit != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "diagnosticProvider") {
		t.Fatalf("run=(%d,%q,%q)", exit, stdout.String(), stderr.String())
	}
}

func TestRunLSPStaticFinalV7PreservesVerifiedReviewSnapshot(t *testing.T) {
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	check, err := diagnostics.NewDeterministicCheck("3f01f93e51003eb3a0deca04719a3957d6e367c97c33bdfea105174d95698092", strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckPassed, 1, 2, 1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	deterministic, err := diagnostics.NewSetWithDeterministicObservations(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("8", 64), []diagnostics.DeterministicCheck{check}, nil)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := diagnostics.NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Verified issue", "Independent verification.", diagnostics.SeverityError, "main.go", 3, 4, []string{"evidence-1"})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := diagnostics.NewSetWithDeterministicChecks(scope, strings.Repeat("9", 64), deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), []diagnostics.Finding{finding})
	if err != nil {
		t.Fatal(err)
	}
	final, err := diagnostics.NewFinalReviewSet(scope, deterministic.SnapshotIdentity(), deterministic.HeadRevision(), diagnostics.FinalOutcomeCompleted, deterministic, verified)
	if err != nil || final.Validate() != nil || final.SnapshotIdentity() == final.ReviewSnapshotIdentity() {
		t.Fatalf("distinct snapshot fixture: %v", err)
	}
	encoded, err := diagnostics.EncodeSet(final)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "diagnostics.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	for _, message := range []any{
		map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"rootUri": "file:///workspace", "initializationOptions": map[string]any{"tenant_id": "tenant-a", "repository_id": "repo-a", "review_run_id": "run-a"}}},
		map[string]any{"jsonrpc": "2.0", "id": 2, "method": "textDocument/diagnostic", "params": map[string]any{"textDocument": map[string]any{"uri": "file:///workspace/main.go"}}},
		map[string]any{"jsonrpc": "2.0", "method": "exit"},
	} {
		body, err := json.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&input, "Content-Length: %d\r\n\r\n%s", len(body), body)
	}
	var stdout, stderr bytes.Buffer
	if exit := runLSP([]string{"--diagnostics", path}, &input, &stdout, &stderr); exit != 0 || stderr.Len() != 0 {
		t.Fatalf("run=(%d,%q,%q)", exit, stdout.String(), stderr.String())
	}
	reader := bufio.NewReader(bytes.NewReader(stdout.Bytes()))
	var pull []byte
	for i := 0; i < 2; i++ {
		header, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		var length int
		if _, err := fmt.Sscanf(header, "Content-Length: %d\r\n", &length); err != nil || length <= 0 || length > 1<<20 {
			t.Fatalf("invalid output frame: %q %v", header, err)
		}
		if separator, err := reader.ReadString('\n'); err != nil || separator != "\r\n" {
			t.Fatalf("invalid output separator: %q %v", separator, err)
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(reader, body); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			pull = body
		}
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("unexpected output after pull: %v", err)
	}
	var response struct {
		ID     int `json:"id"`
		Result struct {
			Kind     string `json:"kind"`
			ResultID string `json:"resultId"`
			Items    []struct {
				Data struct {
					DiagnosticIdentity    string   `json:"diagnostic_identity"`
					SourceIdentity        string   `json:"source_identity"`
					EvidenceIDs           []string `json:"evidence_ids"`
					DiagnosticSetIdentity string   `json:"diagnostic_set_identity"`
					SnapshotIdentity      string   `json:"snapshot_identity"`
					HeadRevision          string   `json:"head_revision"`
				} `json:"data"`
			} `json:"items"`
		} `json:"result"`
	}
	if err := json.Unmarshal(pull, &response); err != nil || response.ID != 2 || response.Result.Kind != "full" || response.Result.ResultID != final.Identity() || len(response.Result.Items) != 1 {
		t.Fatalf("invalid final V7 pull: %s %v", pull, err)
	}
	data := response.Result.Items[0].Data
	if data.DiagnosticIdentity != finding.Identity() || data.SourceIdentity != finding.SourceIdentity() || !reflect.DeepEqual(data.EvidenceIDs, finding.EvidenceIDs()) || data.DiagnosticSetIdentity != final.Identity() || data.HeadRevision != final.HeadRevision() {
		t.Fatalf("CLI changed canonical finding evidence: %+v", data)
	}
	if data.SnapshotIdentity != verified.SnapshotIdentity() {
		t.Fatalf("CLI verified finding snapshot=%s, want review snapshot=%s; physical snapshot=%s", data.SnapshotIdentity, verified.SnapshotIdentity(), final.SnapshotIdentity())
	}
}
