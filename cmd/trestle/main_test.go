package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunValidatesLocalFixture(t *testing.T) {
	fixturePath := filepath.Join(t.TempDir(), "fixture.json")
	fixture := `{"schema_version":1,"provider_route":"local","requested_capabilities":[],"request":{"id":"review-1","snapshot":{"workspace":"workspace","revision":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ranges":[{"path":"main.go","start_line":1,"end_line":1}]}}}`
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"validate-fixture", fixturePath}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	fields := strings.Fields(stdout.String())
	if len(fields) != 3 || fields[0] != "valid" || fields[1] != "fixture" || len(fields[2]) != 64 {
		t.Fatalf("stdout = %q, want valid fixture and SHA-256 identity", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunReviewsLocalFixture(t *testing.T) {
	fixturePath := filepath.Join("testdata", "local-review", "fixture.json")
	var firstStdout bytes.Buffer
	var firstStderr bytes.Buffer

	firstExitCode := run([]string{"review", fixturePath}, &firstStdout, &firstStderr)

	if firstExitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", firstExitCode, firstStderr.String())
	}
	if !strings.Contains(firstStdout.String(), "status: verified\n") {
		t.Fatalf("stdout = %q, want verified status", firstStdout.String())
	}
	if !strings.Contains(firstStdout.String(), "finding: finding-") || !strings.Contains(firstStdout.String(), "evidence: evidence-") {
		t.Fatalf("stdout = %q, want canonical finding and evidence identities", firstStdout.String())
	}
	if firstStderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", firstStderr.String())
	}

	var secondStdout bytes.Buffer
	var secondStderr bytes.Buffer
	secondExitCode := run([]string{"review", fixturePath}, &secondStdout, &secondStderr)
	if secondExitCode != 0 {
		t.Fatalf("second run() exit code = %d, want 0; stderr = %q", secondExitCode, secondStderr.String())
	}
	if secondStdout.String() != firstStdout.String() {
		t.Fatalf("second stdout = %q, want stable output %q", secondStdout.String(), firstStdout.String())
	}
}

func TestRunChangesEvidenceIdentityWithContentPathOrRange(t *testing.T) {
	baseSource := "package main; import \"fmt\"; func main() { fmt.Println(\"debug\") }\n// next\n"
	changedSource := "package main; import \"fmt\"; func main() {  fmt.Println(\"debug\") }\n// next\n"
	baseOutput := runSuccessfulReview(t, writeReviewFixture(t, "main.go", baseSource, 1, 1, nil))
	contentOutput := runSuccessfulReview(t, writeReviewFixture(t, "main.go", changedSource, 1, 1, nil))
	pathOutput := runSuccessfulReview(t, writeReviewFixture(t, "nested/main.go", baseSource, 1, 1, nil))
	rangeOutput := runSuccessfulReview(t, writeReviewFixture(t, "main.go", baseSource, 1, 2, nil))

	baseEvidenceID := outputIdentity(t, baseOutput, "evidence: ")
	for name, output := range map[string]string{
		"content": contentOutput,
		"path":    pathOutput,
		"range":   rangeOutput,
	} {
		if evidenceID := outputIdentity(t, output, "evidence: "); evidenceID == baseEvidenceID {
			t.Fatalf("%s evidence identity = %q, want change from %q", name, evidenceID, baseEvidenceID)
		}
	}
}

func TestRunFailsClosedForBlockedAndInvalidReview(t *testing.T) {
	t.Run("blocked capability", func(t *testing.T) {
		fixturePath := writeReviewFixture(t, "main.go", "fmt.Println(\"debug\")\n", 1, 1, []string{"publication"})
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"review", fixturePath}, &stdout, &stderr)

		if exitCode == 0 || !strings.Contains(stderr.String(), "status: blocked\n") {
			t.Fatalf("run() = exit %d, stderr %q; want nonzero blocked outcome", exitCode, stderr.String())
		}
		assertNoCompletionClaim(t, stdout.String()+stderr.String())
	})

	t.Run("revision mismatch", func(t *testing.T) {
		fixturePath := writeReviewFixture(t, "main.go", "fmt.Println(\"debug\")\n", 1, 1, nil)
		if err := os.WriteFile(filepath.Join(filepath.Dir(fixturePath), "main.go"), []byte("changed\n"), 0o600); err != nil {
			t.Fatalf("os.WriteFile() error = %v", err)
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"review", fixturePath}, &stdout, &stderr)

		if exitCode == 0 || !strings.Contains(stderr.String(), "status: failed\n") {
			t.Fatalf("run() = exit %d, stderr %q; want nonzero failed outcome", exitCode, stderr.String())
		}
		assertNoCompletionClaim(t, stdout.String()+stderr.String())
	})
}

func TestRunFailsWhenSuccessfulOutputCannotBeWritten(t *testing.T) {
	fixturePath := filepath.Join("testdata", "local-review", "fixture.json")

	for _, args := range [][]string{
		{"validate-fixture", fixturePath},
		{"review", fixturePath},
	} {
		var stderr bytes.Buffer

		exitCode := run(args, errorWriter{}, &stderr)

		if exitCode == 0 {
			t.Fatalf("run(%q) exit code = 0, want write failure", args)
		}
		if !strings.Contains(stderr.String(), "write result") {
			t.Fatalf("run(%q) stderr = %q, want write failure", args, stderr.String())
		}
	}
}

func TestRunReportsInconclusiveWithoutCompletionClaim(t *testing.T) {
	fixturePath := writeReviewFixture(t, "main.go", "return nil\n", 1, 1, nil)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := run([]string{"review", fixturePath}, &stdout, &stderr)

	if exitCode == 0 || !strings.Contains(stdout.String(), "status: inconclusive\n") {
		t.Fatalf("run() = exit %d, stdout %q; want nonzero inconclusive outcome", exitCode, stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	assertNoCompletionClaim(t, stdout.String())
}

func TestRunConfinesSourceAccessAndDoesNotExecuteContent(t *testing.T) {
	t.Run("symlink escape", func(t *testing.T) {
		outsideDirectory := t.TempDir()
		outsidePath := filepath.Join(outsideDirectory, "outside.go")
		outsideContent := []byte("fmt.Println(\"debug\")\n")
		if err := os.WriteFile(outsidePath, outsideContent, 0o600); err != nil {
			t.Fatalf("os.WriteFile() error = %v", err)
		}
		fixturePath := writeReviewFixture(t, "main.go", string(outsideContent), 1, 1, nil)
		sourcePath := filepath.Join(filepath.Dir(fixturePath), "main.go")
		if err := os.Remove(sourcePath); err != nil {
			t.Fatalf("os.Remove() error = %v", err)
		}
		if err := os.Symlink(outsidePath, sourcePath); err != nil {
			t.Fatalf("os.Symlink() error = %v", err)
		}
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		exitCode := run([]string{"review", fixturePath}, &stdout, &stderr)

		if exitCode == 0 || !strings.Contains(stderr.String(), "status: failed\n") {
			t.Fatalf("run() = exit %d, stderr %q; want confined-access failure", exitCode, stderr.String())
		}
	})

	t.Run("source text is inert", func(t *testing.T) {
		sentinelPath := filepath.Join(t.TempDir(), "must-not-exist")
		content := "package main; import \"fmt\"; func main() { fmt.Println(\"debug\") }\n// $(touch " + sentinelPath + ")\n"
		fixturePath := writeReviewFixture(t, "main.go", content, 1, 2, nil)

		runSuccessfulReview(t, fixturePath)

		if _, err := os.Stat(sentinelPath); !os.IsNotExist(err) {
			t.Fatalf("os.Stat(%q) error = %v, want file not to exist", sentinelPath, err)
		}
	})
}

func runSuccessfulReview(t *testing.T, fixturePath string) string {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exitCode := run([]string{"review", fixturePath}, &stdout, &stderr); exitCode != 0 {
		t.Fatalf("run() exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	return stdout.String()
}

func writeReviewFixture(t *testing.T, sourcePath, content string, startLine, endLine int, requestedCapabilities []string) string {
	t.Helper()
	fixtureDirectory := t.TempDir()
	absoluteSourcePath := filepath.Join(fixtureDirectory, filepath.FromSlash(sourcePath))
	if err := os.MkdirAll(filepath.Dir(absoluteSourcePath), 0o700); err != nil {
		t.Fatalf("os.MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(absoluteSourcePath, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	revision := sha256.Sum256([]byte(content))
	wire := reviewFixtureWire{
		SchemaVersion:         1,
		ProviderRoute:         "local",
		RequestedCapabilities: requestedCapabilities,
		Request: reviewRequestWire{
			ID: "local-review-test",
			Snapshot: reviewSnapshotWire{
				Workspace: "local-review-test",
				Revision:  hex.EncodeToString(revision[:]),
				Ranges: []reviewRangeWire{{
					Path:      sourcePath,
					StartLine: startLine,
					EndLine:   endLine,
				}},
			},
		},
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	fixturePath := filepath.Join(fixtureDirectory, "fixture.json")
	if err := os.WriteFile(fixturePath, encoded, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	return fixturePath
}

func outputIdentity(t *testing.T, output, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strings.Fields(strings.TrimPrefix(line, prefix))[0]
		}
	}
	t.Fatalf("output = %q, want line prefixed by %q", output, prefix)
	return ""
}

func assertNoCompletionClaim(t *testing.T, output string) {
	t.Helper()
	if strings.Contains(strings.ToLower(output), "complete") {
		t.Fatalf("output = %q, must not claim completion", output)
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

type reviewFixtureWire struct {
	SchemaVersion         int               `json:"schema_version"`
	ProviderRoute         string            `json:"provider_route"`
	RequestedCapabilities []string          `json:"requested_capabilities"`
	Request               reviewRequestWire `json:"request"`
}

type reviewRequestWire struct {
	ID       string             `json:"id"`
	Snapshot reviewSnapshotWire `json:"snapshot"`
}

type reviewSnapshotWire struct {
	Workspace string            `json:"workspace"`
	Revision  string            `json:"revision"`
	Ranges    []reviewRangeWire `json:"ranges"`
}

type reviewRangeWire struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}
