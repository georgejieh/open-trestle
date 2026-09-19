package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	if receipt.SchemaVersion != 2 || receipt.Status != "verified" {
		t.Fatalf("receipt schema and status = (%d, %q), want (2, verified)", receipt.SchemaVersion, receipt.Status)
	}
	if receipt.FixtureID == "" || receipt.RequestID != "local-review-1" || receipt.SnapshotID == "" || receipt.Revision == "" {
		t.Fatalf("receipt binding is incomplete: %#v", receipt)
	}
	if len(receipt.Findings) != 1 || receipt.Findings[0].ID == "" || receipt.Findings[0].Source.Path != "main.go" || receipt.Findings[0].Evidence.ID == "" {
		t.Fatalf("receipt findings are incomplete: %#v", receipt.Findings)
	}
	finding := receipt.Findings[0]

	var reviewStdout bytes.Buffer
	var reviewStderr bytes.Buffer
	if exitCode := run([]string{"review", fixturePath}, &reviewStdout, &reviewStderr); exitCode != 0 {
		t.Fatalf("review exit code = %d, want 0; stderr = %q", exitCode, reviewStderr.String())
	}
	if finding.ID != outputIdentity(t, reviewStdout.String(), "finding: ") {
		t.Fatalf("CI finding ID = %q, want review parity", finding.ID)
	}
	if finding.Evidence.ID != outputIdentity(t, reviewStdout.String(), "evidence: ") {
		t.Fatalf("CI evidence ID = %q, want review parity", finding.Evidence.ID)
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

func TestRunCIEmitsEveryFindingWithTextParity(t *testing.T) {
	content := "package sample\nimport \"fmt\"\nfunc main() {\n\tfmt.Println(\"debug\")\n\tfmt.Println(\n\t\t\"debug\",\n\t)\n}\n"
	fixturePath := writeReviewFixture(t, "main.go", content, 1, 8, nil)
	var ciStdout bytes.Buffer
	var ciStderr bytes.Buffer

	if exitCode := run([]string{"ci", "--format=json", fixturePath}, &ciStdout, &ciStderr); exitCode != 0 {
		t.Fatalf("CI exit code = %d, want 0; stderr = %q", exitCode, ciStderr.String())
	}
	receipt := decodeCIReceipt(t, ciStdout.String())
	if len(receipt.Findings) != 2 {
		t.Fatalf("CI findings = %#v, want two", receipt.Findings)
	}
	if receipt.Findings[0].Source.StartLine != 4 || receipt.Findings[0].Source.EndLine != 4 || receipt.Findings[1].Source.StartLine != 5 || receipt.Findings[1].Source.EndLine != 7 {
		t.Fatalf("CI source ranges = %#v, want exact ordered spans", receipt.Findings)
	}

	var reviewStdout bytes.Buffer
	var reviewStderr bytes.Buffer
	if exitCode := run([]string{"review", fixturePath}, &reviewStdout, &reviewStderr); exitCode != 0 {
		t.Fatalf("review exit code = %d, want 0; stderr = %q", exitCode, reviewStderr.String())
	}
	findingIDs := textOutputIdentities(reviewStdout.String(), "finding: ")
	evidenceIDs := textOutputIdentities(reviewStdout.String(), "evidence: ")
	if len(findingIDs) != len(receipt.Findings) || len(evidenceIDs) != len(receipt.Findings) {
		t.Fatalf("text result counts = %d and %d, want %d", len(findingIDs), len(evidenceIDs), len(receipt.Findings))
	}
	for i, finding := range receipt.Findings {
		if finding.ID != findingIDs[i] || finding.Evidence.ID != evidenceIDs[i] {
			t.Fatalf("CI result %d lacks text parity", i)
		}
	}

	var repeatedStdout bytes.Buffer
	var repeatedStderr bytes.Buffer
	if exitCode := run([]string{"ci", "--format=json", fixturePath}, &repeatedStdout, &repeatedStderr); exitCode != 0 {
		t.Fatalf("repeated CI exit code = %d, want 0; stderr = %q", exitCode, repeatedStderr.String())
	}
	if repeatedStdout.String() != ciStdout.String() {
		t.Fatalf("repeated CI output = %q, want %q", repeatedStdout.String(), ciStdout.String())
	}
}

func TestRunCIBindsLineDirectiveFindingsToPhysicalSource(t *testing.T) {
	callLine := `func main() { fmt.Println("debug") }`
	content := "package sample\nimport \"fmt\"\n//line fake.go:100\n" + callLine + "\n"
	fixturePath := writeReviewFixture(t, "main.go", content, 1, 4, nil)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if exitCode := run([]string{"ci", "--format=json", fixturePath}, &stdout, &stderr); exitCode != 0 {
		t.Fatalf("CI exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	receipt := decodeCIReceipt(t, stdout.String())
	if len(receipt.Findings) != 1 || receipt.Findings[0].Source.Path != "main.go" || receipt.Findings[0].Source.StartLine != 4 || receipt.Findings[0].Source.EndLine != 4 {
		t.Fatalf("CI findings = %#v, want physical main.go:4-4", receipt.Findings)
	}
	digest := sha256.Sum256([]byte(callLine))
	if receipt.Findings[0].Evidence.Digest != hex.EncodeToString(digest[:]) {
		t.Fatalf("evidence digest = %q, want physical call line digest", receipt.Findings[0].Evidence.Digest)
	}
}

func TestRunCIRendersNonVerifiedOutcomes(t *testing.T) {
	t.Run("inconclusive", func(t *testing.T) {
		fixturePath := writeReviewFixture(t, "main.go", "package sample\nfunc noop() {}\n", 1, 1, nil)
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

func TestRunCIReturnsInconclusiveForInertDebugText(t *testing.T) {
	testCases := []struct {
		name       string
		sourcePath string
		content    string
		line       int
	}{
		{name: "block comment", sourcePath: "main.go", content: "package sample\n\n/*\nfmt.Println(\"debug\")\n*/\n", line: 4},
		{name: "shadowed package name", sourcePath: "main.go", content: "package sample\n\ntype noop struct{}\nfunc (noop) Println(string) {}\nfunc demo() {\n\tvar fmt noop\n\tfmt.Println(\"debug\")\n}\n", line: 7},
		{name: "raw string", sourcePath: "main.go", content: "package sample\n\nvar message = `\nfmt.Println(\"debug\")\n`\n", line: 4},
		{name: "interpreted string", sourcePath: "main.go", content: "package sample\n\nvar message = \"fmt.Println(\\\"debug\\\")\"\n", line: 3},
		{name: "non-Go source", sourcePath: "README.md", content: "fmt.Println(\"debug\")\n", line: 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixturePath := writeReviewFixture(t, testCase.sourcePath, testCase.content, testCase.line, testCase.line, nil)
			assertCIOutcome(t, fixturePath, 3, "inconclusive")
		})
	}
}

func TestRunCIFailsForMalformedGoSource(t *testing.T) {
	fixturePath := writeReviewFixture(t, "main.go", "package sample\nfunc {\n", 1, 1, nil)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"ci", "--format=json", fixturePath}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("run() exit code = %d, want 1; stderr = %q", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), `"findings":[]`) {
		t.Fatalf("stdout = %q, want empty findings array", stdout.String())
	}
	receipt := decodeCIReceipt(t, stdout.String())
	if receipt.SchemaVersion != 2 {
		t.Fatalf("receipt schema version = %d, want 2", receipt.SchemaVersion)
	}
	if receipt.Status != "failed" || !strings.Contains(receipt.Reason, "parse Go source") {
		t.Fatalf("receipt = %#v, want failed parse outcome", receipt)
	}
	if len(receipt.Findings) != 0 {
		t.Fatalf("receipt findings = %#v, want empty", receipt.Findings)
	}
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
	if !strings.Contains(stdout.String(), `"findings":[]`) {
		t.Fatalf("stdout = %q, want empty findings array", stdout.String())
	}
	receipt := decodeCIReceipt(t, stdout.String())
	if receipt.SchemaVersion != 2 {
		t.Fatalf("receipt schema version = %d, want 2", receipt.SchemaVersion)
	}
	if receipt.Status != wantStatus || receipt.Reason == "" {
		t.Fatalf("receipt = %#v, want status %q with reason", receipt, wantStatus)
	}
	if len(receipt.Findings) != 0 {
		t.Fatalf("receipt findings = %#v, want empty", receipt.Findings)
	}
}

func textOutputIdentities(output, prefix string) []string {
	var identities []string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			identities = append(identities, strings.Fields(strings.TrimPrefix(line, prefix))[0])
		}
	}
	return identities
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
	SchemaVersion int             `json:"schema_version"`
	Status        string          `json:"status"`
	FixtureID     string          `json:"fixture_id"`
	RequestID     string          `json:"request_id"`
	SnapshotID    string          `json:"snapshot_id"`
	Revision      string          `json:"revision"`
	Reason        string          `json:"reason"`
	Findings      []ciFindingWire `json:"findings"`
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
