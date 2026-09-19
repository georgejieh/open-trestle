package review

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/config"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestSelectSourceRangeUsesPhysicalLines(t *testing.T) {
	testCases := []struct {
		name      string
		content   string
		startLine int
		endLine   int
		want      string
		wantError bool
	}{
		{name: "empty file", startLine: 1, endLine: 1, wantError: true},
		{name: "single line", content: "alpha", startLine: 1, endLine: 1, want: "alpha"},
		{name: "terminal newline", content: "alpha\n", startLine: 1, endLine: 1, want: "alpha"},
		{name: "line after terminal newline", content: "alpha\n", startLine: 2, endLine: 2, wantError: true},
		{name: "last physical line", content: "alpha\nbeta\n", startLine: 2, endLine: 2, want: "beta"},
		{name: "range crosses end", content: "alpha\nbeta\n", startLine: 1, endLine: 3, wantError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			sourceRange, err := evidence.NewSourceRange("main.go", testCase.startLine, testCase.endLine)
			if err != nil {
				t.Fatalf("evidence.NewSourceRange() error = %v", err)
			}

			selected, err := selectSourceRange([]byte(testCase.content), sourceRange)
			if testCase.wantError {
				if err == nil {
					t.Fatalf("selectSourceRange() error = nil, want range error; selected = %q", selected)
				}
				return
			}
			if err != nil {
				t.Fatalf("selectSourceRange() error = %v", err)
			}
			if string(selected) != testCase.want {
				t.Fatalf("selectSourceRange() = %q, want %q", selected, testCase.want)
			}
		})
	}
}

func TestReviewLocalFixtureReturnsImmutableFindingCollection(t *testing.T) {
	content := "package sample\nimport \"fmt\"\nfunc main() {\n\tfmt.Println(\"debug\")\n\tfmt.Println(\"debug\")\n}\n"
	fixturePath := writeLocalFixture(t, content, 1, 6)

	result, err := ReviewLocalFixture(fixturePath, config.DefaultLocal())
	if err != nil {
		t.Fatalf("ReviewLocalFixture() error = %v", err)
	}
	findings := result.Findings()
	items := result.EvidenceItems()
	if len(findings) != 2 || len(items) != 2 {
		t.Fatalf("ReviewLocalFixture() returned %d findings and %d evidence items, want 2 each", len(findings), len(items))
	}
	for i, wantLine := range []int{4, 5} {
		if findings[i].SourceRange().StartLine() != wantLine || items[i].SourceRange() != findings[i].SourceRange() {
			t.Fatalf("result %d ranges are not paired at line %d", i, wantLine)
		}
		if ids := findings[i].EvidenceIDs(); len(ids) != 1 || ids[0] != items[i].ID() {
			t.Fatalf("result %d evidence IDs = %#v, want %q", i, ids, items[i].ID())
		}
	}

	firstFindingID := findings[0].ID()
	firstEvidenceID := items[0].ID()
	findings[0] = Finding{}
	items[0] = evidence.EvidenceItem{}
	if result.Findings()[0].ID() != firstFindingID || result.EvidenceItems()[0].ID() != firstEvidenceID {
		t.Fatal("returned slices must not mutate the local result")
	}
}

func writeLocalFixture(t *testing.T, content string, startLine, endLine int) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "main.go"), []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile(source) error = %v", err)
	}
	revision := sha256.Sum256([]byte(content))
	fixture := fmt.Sprintf(`{"schema_version":1,"provider_route":"local","requested_capabilities":[],"request":{"id":"local-test","snapshot":{"workspace":"local-test","revision":"%x","ranges":[{"path":"main.go","start_line":%d,"end_line":%d}]}}}`, revision, startLine, endLine)
	fixturePath := filepath.Join(directory, "fixture.json")
	if err := os.WriteFile(fixturePath, []byte(fixture), 0o600); err != nil {
		t.Fatalf("os.WriteFile(fixture) error = %v", err)
	}
	return fixturePath
}

func TestOpenConfinedRegularFileRejectsDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "nested"), 0o700); err != nil {
		t.Fatalf("os.Mkdir() error = %v", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("os.OpenRoot() error = %v", err)
	}
	defer root.Close()

	if _, err := openConfinedRegularFile(root, "nested"); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("openConfinedRegularFile() error = %v, want regular-file error", err)
	}
}
