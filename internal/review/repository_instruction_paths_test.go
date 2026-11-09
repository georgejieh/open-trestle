package review

import (
	"slices"
	"testing"
)

func TestRepositoryInstructionPathsAreFixedRootFiles(t *testing.T) {
	want := []string{"AGENTS.md", "CLAUDE.md", ".github/copilot-instructions.md", ".trestle/review-instructions.md"}
	got := RepositoryInstructionPaths()
	if !slices.Equal(got, want) {
		t.Fatalf("paths=%q", got)
	}
	got[0] = "README.md"
	if !slices.Equal(RepositoryInstructionPaths(), want) {
		t.Fatal("caller mutated the fixed instruction path list")
	}
	for _, path := range want {
		if !RepositoryInstructionPath(path) {
			t.Fatalf("%s not an instruction path", path)
		}
	}
	for _, path := range []string{"docs/AGENTS.md", "pkg/CLAUDE.md", "agents.md", "README.md", ".github/workflows/copilot-instructions.md", "copilot-instructions.md", ""} {
		if RepositoryInstructionPath(path) {
			t.Fatalf("%q accepted as an instruction path", path)
		}
	}
}
