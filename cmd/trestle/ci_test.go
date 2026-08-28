package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCIEmitsDeterministicVerifiedReceipt(t *testing.T) {
	fixturePath := "testdata/local-review/fixture.json"
	var firstStdout bytes.Buffer
	var firstStderr bytes.Buffer

	firstExitCode := run([]string{"ci", "--format=json", fixturePath}, &firstStdout, &firstStderr)

	if firstExitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", firstExitCode, firstStderr.String())
	}
	if firstStderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", firstStderr.String())
	}

	receipt := decodeCIReceipt(t, firstStdout.String())
	if receipt.SchemaVersion != 1 || receipt.Status != "verified" {
		t.Fatalf("receipt schema and status = (%d, %q), want (1, verified)", receipt.SchemaVersion, receipt.Status)
	}
	if receipt.FixtureID == "" || receipt.RequestID != "local-review-1" || receipt.SnapshotID == "" || receipt.Revision == "" {
		t.Fatalf("receipt binding is incomplete: %#v", receipt)
	}
	if receipt.Finding == nil || receipt.Finding.ID == "" || receipt.Finding.Source.Path != "main.go" || receipt.Finding.Evidence.ID == "" {
		t.Fatalf("receipt finding is incomplete: %#v", receipt.Finding)
	}

	var reviewStdout bytes.Buffer
	var reviewStderr bytes.Buffer
	if exitCode := run([]string{"review", fixturePath}, &reviewStdout, &reviewStderr); exitCode != 0 {
		t.Fatalf("review exit code = %d, want 0; stderr = %q", exitCode, reviewStderr.String())
	}
	if receipt.Finding.ID != outputIdentity(t, reviewStdout.String(), "finding: ") {
		t.Fatalf("CI finding ID = %q, want review parity", receipt.Finding.ID)
	}
	if receipt.Finding.Evidence.ID != outputIdentity(t, reviewStdout.String(), "evidence: ") {
		t.Fatalf("CI evidence ID = %q, want review parity", receipt.Finding.Evidence.ID)
	}

	var secondStdout bytes.Buffer
	var secondStderr bytes.Buffer
	if exitCode := run([]string{"ci", "--format=json", fixturePath}, &secondStdout, &secondStderr); exitCode != 0 {
		t.Fatalf("second run() exit code = %d, want 0; stderr = %q", exitCode, secondStderr.String())
	}
	if secondStdout.String() != firstStdout.String() {
		t.Fatalf("second output = %q, want deterministic output %q", secondStdout.String(), firstStdout.String())
	}
}

func TestRunCIRendersNonVerifiedOutcomes(t *testing.T) {
	t.Run("inconclusive", func(t *testing.T) {
		fixturePath := writeReviewFixture(t, "main.go", "return nil\n", 1, 1, nil)
		assertCIOutcome(t, fixturePath, 3, "inconclusive")
	})

	t.Run("blocked", func(t *testing.T) {
		fixturePath := writeReviewFixture(t, "main.go", "fmt.Println(\"debug\")\n", 1, 1, []string{"publication"})
		assertCIOutcome(t, fixturePath, 4, "blocked")
	})

	t.Run("failed", func(t *testing.T) {
		fixturePath := writeReviewFixture(t, "main.go", "fmt.Println(\"debug\")\n", 1, 1, nil)
		if err := os.WriteFile(filepath.Join(filepath.Dir(fixturePath), "main.go"), []byte("changed\n"), 0o600); err != nil {
			t.Fatalf("os.WriteFile() error = %v", err)
		}
		assertCIOutcome(t, fixturePath, 1, "failed")
	})
}

func TestRunCIRejectsUnsupportedArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"ci", "--format=yaml", "fixture.json"}, &stdout, &stderr)

	if exitCode != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("run() = exit %d, stdout %q, stderr %q; want usage error", exitCode, stdout.String(), stderr.String())
	}
}

func assertCIOutcome(t *testing.T, fixturePath string, wantExitCode int, wantStatus string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"ci", "--format=json", fixturePath}, &stdout, &stderr)

	if exitCode != wantExitCode {
		t.Fatalf("run() exit code = %d, want %d; stderr = %q", exitCode, wantExitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	receipt := decodeCIReceipt(t, stdout.String())
	if receipt.Status != wantStatus || receipt.Reason == "" {
		t.Fatalf("receipt = %#v, want status %q with reason", receipt, wantStatus)
	}
	if receipt.Finding != nil {
		t.Fatalf("receipt finding = %#v, want omitted", receipt.Finding)
	}
}

func decodeCIReceipt(t *testing.T, output string) ciReceiptWire {
	t.Helper()
	var receipt ciReceiptWire
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		t.Fatalf("Decode() error = %v; output = %q", err, output)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("trailing output decode error = %v; output = %q", err, output)
	}
	return receipt
}

type ciReceiptWire struct {
	SchemaVersion int            `json:"schema_version"`
	Status        string         `json:"status"`
	FixtureID     string         `json:"fixture_id"`
	RequestID     string         `json:"request_id"`
	SnapshotID    string         `json:"snapshot_id"`
	Revision      string         `json:"revision"`
	Reason        string         `json:"reason"`
	Finding       *ciFindingWire `json:"finding"`
}

type ciFindingWire struct {
	ID       string         `json:"id"`
	Title    string         `json:"title"`
	Severity string         `json:"severity"`
	Source   ciSourceWire   `json:"source"`
	Evidence ciEvidenceWire `json:"evidence"`
}

type ciSourceWire struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

type ciEvidenceWire struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}
