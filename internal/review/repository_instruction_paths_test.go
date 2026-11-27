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

func TestDeclaredIntentPathsAreFixedAndDistinctFromInstructions(t *testing.T) {
	want := []string{".trestle/scope.md", ".specify/memory/constitution.md", ".kiro/steering/product.md", "openspec/project.md",
		"agent-os/product/mission.md", ".taskmaster/docs/prd.txt", "memory-bank/projectbrief.md", "PRD.md", "docs/PRD.md", "docs/prd.md"}
	got := DeclaredIntentPaths()
	if !slices.Equal(got, want) || MaxDeclaredIntentDocuments != 3 {
		t.Fatalf("paths=%q max=%d", got, MaxDeclaredIntentDocuments)
	}
	got[0] = "README.md"
	if !slices.Equal(DeclaredIntentPaths(), want) {
		t.Fatal("caller mutated the fixed intent path list")
	}
	for _, path := range want {
		if RepositoryInstructionPath(path) {
			t.Fatalf("%s is also an instruction path", path)
		}
	}
}
