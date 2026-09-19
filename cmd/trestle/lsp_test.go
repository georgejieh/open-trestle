package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
	"os"
	"path/filepath"
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
