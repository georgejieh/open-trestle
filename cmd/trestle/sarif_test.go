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

	"github.com/georgejieh/open-trestle/internal/review"
)

func TestRunSARIFEmitsDeterministicVerifiedResult(t *testing.T) {
	fixturePath := "testdata/local-review/fixture.json"
	var firstStdout bytes.Buffer
	var firstStderr bytes.Buffer

	firstExitCode := run([]string{"ci", "--format=sarif", fixturePath}, &firstStdout, &firstStderr)

	if firstExitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", firstExitCode, firstStderr.String())
	}
	if firstStderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", firstStderr.String())
	}
	log := decodeSARIFLog(t, firstStdout.String())
	if log.Schema != "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json" || log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("SARIF header = (%q, %q, %d runs), want schema, version 2.1.0, and one run", log.Schema, log.Version, len(log.Runs))
	}
	sarifRun := log.Runs[0]
	if sarifRun.Tool.Driver.Name != "Open Trestle" || len(sarifRun.Tool.Driver.Rules) != 1 || sarifRun.Tool.Driver.Rules[0].ID != "static-debug-output" {
		t.Fatalf("SARIF driver = %#v, want Open Trestle static rule", sarifRun.Tool.Driver)
	}
	if sarifRun.Properties.Status != "verified" || sarifRun.Properties.FixtureID == "" || sarifRun.Properties.RequestID != "local-review-1" || sarifRun.Properties.SnapshotID == "" || sarifRun.Properties.Revision == "" {
		t.Fatalf("SARIF run properties are incomplete: %#v", sarifRun.Properties)
	}
	if len(sarifRun.Results) != 1 {
		t.Fatalf("SARIF results = %#v, want one", sarifRun.Results)
	}
	result := sarifRun.Results[0]
	if result.RuleID != "static-debug-output" || result.Level != "warning" || result.Message.Text != "Debug output left in source" {
		t.Fatalf("SARIF result identity = %#v, want static warning", result)
	}
	if len(result.Locations) != 1 {
		t.Fatalf("SARIF locations = %#v, want one", result.Locations)
	}
	location := result.Locations[0].PhysicalLocation
	if location.ArtifactLocation.URI != "main.go" || location.Region.StartLine != 6 || location.Region.EndLine != 6 {
		t.Fatalf("SARIF location = %#v, want main.go:6-6", location)
	}
	findingID := result.Fingerprints["openTrestleFindingId/v1"]
	if findingID == "" || result.Properties.EvidenceID == "" || result.Properties.EvidenceDigest == "" {
		t.Fatalf("SARIF result bindings are incomplete: %#v", result)
	}

	var jsonStdout bytes.Buffer
	var jsonStderr bytes.Buffer
	if exitCode := run([]string{"ci", "--format=json", fixturePath}, &jsonStdout, &jsonStderr); exitCode != 0 {
		t.Fatalf("JSON exit code = %d, want 0; stderr = %q", exitCode, jsonStderr.String())
	}
	receipt := decodeCIReceipt(t, jsonStdout.String())
	if findingID != receipt.Findings[0].ID || result.Properties.EvidenceID != receipt.Findings[0].Evidence.ID || result.Properties.EvidenceDigest != receipt.Findings[0].Evidence.Digest {
		t.Fatal("SARIF finding and evidence identities must match JSON")
	}

	var secondStdout bytes.Buffer
	var secondStderr bytes.Buffer
	if exitCode := run([]string{"ci", "--format=sarif", fixturePath}, &secondStdout, &secondStderr); exitCode != 0 {
		t.Fatalf("second run() exit code = %d, want 0; stderr = %q", exitCode, secondStderr.String())
	}
	if secondStdout.String() != firstStdout.String() {
		t.Fatalf("second output = %q, want deterministic output %q", secondStdout.String(), firstStdout.String())
	}
}

func TestRunFormatsExpandIntersectingSelectionToExactCall(t *testing.T) {
	span := "\tfmt.Println(\n\t\t\"debug\",\n\t)"
	content := "package sample\nimport \"fmt\"\nfunc main() {\n" + span + "\n}\n"
	fixturePath := writeReviewFixture(t, "main.go", content, 5, 5, nil)

	var reviewStdout bytes.Buffer
	var reviewStderr bytes.Buffer
	if exitCode := run([]string{"review", fixturePath}, &reviewStdout, &reviewStderr); exitCode != 0 {
		t.Fatalf("review exit code = %d, want 0; stderr = %q", exitCode, reviewStderr.String())
	}
	if !strings.Contains(reviewStdout.String(), "source: main.go:4-6\n") {
		t.Fatalf("review output = %q, want expanded main.go:4-6", reviewStdout.String())
	}

	var jsonStdout bytes.Buffer
	var jsonStderr bytes.Buffer
	if exitCode := run([]string{"ci", "--format=json", fixturePath}, &jsonStdout, &jsonStderr); exitCode != 0 {
		t.Fatalf("JSON exit code = %d, want 0; stderr = %q", exitCode, jsonStderr.String())
	}
	receipt := decodeCIReceipt(t, jsonStdout.String())
	if len(receipt.Findings) != 1 || receipt.Findings[0].Source.StartLine != 4 || receipt.Findings[0].Source.EndLine != 6 {
		t.Fatalf("JSON findings = %#v, want expanded main.go:4-6", receipt.Findings)
	}
	digest := sha256.Sum256([]byte(span))
	if receipt.Findings[0].Evidence.Digest != hex.EncodeToString(digest[:]) {
		t.Fatalf("JSON evidence digest = %q, want full call span digest", receipt.Findings[0].Evidence.Digest)
	}

	var sarifStdout bytes.Buffer
	var sarifStderr bytes.Buffer
	if exitCode := run([]string{"ci", "--format=sarif", fixturePath}, &sarifStdout, &sarifStderr); exitCode != 0 {
		t.Fatalf("SARIF exit code = %d, want 0; stderr = %q", exitCode, sarifStderr.String())
	}
	log := decodeSARIFLog(t, sarifStdout.String())
	result := log.Runs[0].Results[0]
	location := result.Locations[0].PhysicalLocation
	if location.Region.StartLine != 4 || location.Region.EndLine != 6 || result.Fingerprints["openTrestleFindingId/v1"] != receipt.Findings[0].ID || result.Properties.EvidenceID != receipt.Findings[0].Evidence.ID {
		t.Fatalf("SARIF result = %#v, want JSON parity at main.go:4-6", result)
	}
}

func TestRunSARIFEmitsEveryFindingWithJSONParity(t *testing.T) {
	content := "package sample\nimport \"fmt\"\nfunc main() {\n\tfmt.Println(\"debug\")\n\tfmt.Println(\n\t\t\"debug\",\n\t)\n}\n"
	fixturePath := writeReviewFixture(t, "main.go", content, 1, 8, nil)
	var sarifStdout bytes.Buffer
	var sarifStderr bytes.Buffer

	if exitCode := run([]string{"ci", "--format=sarif", fixturePath}, &sarifStdout, &sarifStderr); exitCode != 0 {
		t.Fatalf("SARIF exit code = %d, want 0; stderr = %q", exitCode, sarifStderr.String())
	}
	log := decodeSARIFLog(t, sarifStdout.String())
	if len(log.Runs[0].Results) != 2 {
		t.Fatalf("SARIF results = %#v, want two", log.Runs[0].Results)
	}

	var jsonStdout bytes.Buffer
	var jsonStderr bytes.Buffer
	if exitCode := run([]string{"ci", "--format=json", fixturePath}, &jsonStdout, &jsonStderr); exitCode != 0 {
		t.Fatalf("JSON exit code = %d, want 0; stderr = %q", exitCode, jsonStderr.String())
	}
	receipt := decodeCIReceipt(t, jsonStdout.String())
	if len(receipt.Findings) != len(log.Runs[0].Results) {
		t.Fatalf("JSON finding count = %d, want %d", len(receipt.Findings), len(log.Runs[0].Results))
	}
	for i, result := range log.Runs[0].Results {
		if result.Fingerprints["openTrestleFindingId/v1"] != receipt.Findings[i].ID || result.Properties.EvidenceID != receipt.Findings[i].Evidence.ID || result.Properties.EvidenceDigest != receipt.Findings[i].Evidence.Digest {
			t.Fatalf("SARIF result %d lacks JSON parity", i)
		}
	}
}

func TestRunSARIFRendersNonVerifiedOutcomes(t *testing.T) {
	t.Run("inconclusive", func(t *testing.T) {
		fixturePath := writeReviewFixture(t, "main.go", "package sample\nfunc noop() {}\n", 1, 1, nil)
		assertSARIFOutcome(t, fixturePath, 3, "inconclusive")
	})

	t.Run("blocked", func(t *testing.T) {
		fixturePath := writeReviewFixture(t, "main.go", "fmt.Println(\"debug\")\n", 1, 1, []string{"publication"})
		assertSARIFOutcome(t, fixturePath, 4, "blocked")
	})

	t.Run("failed", func(t *testing.T) {
		fixturePath := writeReviewFixture(t, "main.go", "fmt.Println(\"debug\")\n", 1, 1, nil)
		if err := os.WriteFile(filepath.Join(filepath.Dir(fixturePath), "main.go"), []byte("changed\n"), 0o600); err != nil {
			t.Fatalf("os.WriteFile() error = %v", err)
		}
		assertSARIFOutcome(t, fixturePath, 1, "failed")
	})
}

func TestSARIFSeverityAndArtifactURI(t *testing.T) {
	for severity, want := range map[review.Severity]string{
		review.SeverityLow:      "note",
		review.SeverityMedium:   "warning",
		review.SeverityHigh:     "error",
		review.SeverityCritical: "error",
	} {
		got, err := sarifLevel(severity)
		if err != nil {
			t.Fatalf("sarifLevel(%q) error = %v", severity, err)
		}
		if got != want {
			t.Fatalf("sarifLevel(%q) = %q, want %q", severity, got, want)
		}
	}
	if _, err := sarifLevel(review.Severity("unknown")); err == nil {
		t.Fatal("sarifLevel(unknown) error = nil, want validation error")
	}

	for sourcePath, want := range map[string]string{
		"docs/naïve file.go": "docs/na%C3%AFve%20file.go",
		"a:b.go":             "./a:b.go",
		"a#b?.go":            "a%23b%3F.go",
	} {
		if got := sarifArtifactURI(sourcePath); got != want {
			t.Fatalf("sarifArtifactURI(%q) = %q, want %q", sourcePath, got, want)
		}
	}
}

func assertSARIFOutcome(t *testing.T, fixturePath string, wantExitCode int, wantStatus string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"ci", "--format=sarif", fixturePath}, &stdout, &stderr)

	if exitCode != wantExitCode {
		t.Fatalf("run() exit code = %d, want %d; stderr = %q", exitCode, wantExitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	log := decodeSARIFLog(t, stdout.String())
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 0 {
		t.Fatalf("SARIF runs = %#v, want one run with no results", log.Runs)
	}
	properties := log.Runs[0].Properties
	if properties.Status != wantStatus || properties.Reason == "" {
		t.Fatalf("SARIF properties = %#v, want status %q with reason", properties, wantStatus)
	}
}

func decodeSARIFLog(t *testing.T, output string) sarifLogWire {
	t.Helper()
	var log sarifLogWire
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&log); err != nil {
		t.Fatalf("Decode() error = %v; output = %q", err, output)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("trailing output decode error = %v; output = %q", err, output)
	}
	return log
}

type sarifLogWire struct {
	Schema  string         `json:"$schema"`
	Version string         `json:"version"`
	Runs    []sarifRunWire `json:"runs"`
}

type sarifRunWire struct {
	Tool       sarifToolWire          `json:"tool"`
	Results    []sarifResultWire      `json:"results"`
	Properties sarifRunPropertiesWire `json:"properties"`
}

type sarifToolWire struct {
	Driver sarifDriverWire `json:"driver"`
}

type sarifDriverWire struct {
	Name  string          `json:"name"`
	Rules []sarifRuleWire `json:"rules"`
}

type sarifRuleWire struct {
	ID                   string                 `json:"id"`
	ShortDescription     sarifMessageWire       `json:"shortDescription"`
	DefaultConfiguration sarifConfigurationWire `json:"defaultConfiguration"`
}

type sarifConfigurationWire struct {
	Level string `json:"level"`
}

type sarifResultWire struct {
	RuleID       string                    `json:"ruleId"`
	Level        string                    `json:"level"`
	Message      sarifMessageWire          `json:"message"`
	Locations    []sarifLocationWire       `json:"locations"`
	Fingerprints map[string]string         `json:"fingerprints"`
	Properties   sarifResultPropertiesWire `json:"properties"`
}

type sarifMessageWire struct {
	Text string `json:"text"`
}

type sarifLocationWire struct {
	PhysicalLocation sarifPhysicalLocationWire `json:"physicalLocation"`
}

type sarifPhysicalLocationWire struct {
	ArtifactLocation sarifArtifactLocationWire `json:"artifactLocation"`
	Region           sarifRegionWire           `json:"region"`
}

type sarifArtifactLocationWire struct {
	URI string `json:"uri"`
}

type sarifRegionWire struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}

type sarifRunPropertiesWire struct {
	Status     string `json:"trestleStatus"`
	Reason     string `json:"trestleReason"`
	FixtureID  string `json:"trestleFixtureId"`
	RequestID  string `json:"trestleRequestId"`
	SnapshotID string `json:"trestleSnapshotId"`
	Revision   string `json:"trestleRevision"`
}

type sarifResultPropertiesWire struct {
	EvidenceID     string `json:"trestleEvidenceId"`
	EvidenceDigest string `json:"trestleEvidenceDigest"`
}
