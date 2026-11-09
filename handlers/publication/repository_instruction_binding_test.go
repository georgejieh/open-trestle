package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/evidence"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
)

const instructionBindingNotes = "Prefer small diffs.\nFlag missing tests.\n"

type recordedBindingSource struct {
	SourceID  string `json:"source_id"`
	Stage     string `json:"stage"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

func recordedBindingSources(t *testing.T, f sourceBindingFixture) []recordedBindingSource {
	t.Helper()
	var packet struct {
		Sources []recordedBindingSource `json:"sources"`
	}
	if err := json.Unmarshal(f.contextArtifact.Payload(), &packet); err != nil {
		t.Fatal(err)
	}
	return packet.Sources
}

// withForgedInstructionSource rebuilds the recorded generation context with one
// more repository_context source over the head bytes of path.
func withForgedInstructionSource(t *testing.T, f sourceBindingFixture, path string, startLine, endLine int) sourceBindingFixture {
	t.Helper()
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	stages := map[string]review.ContextStage{
		review.ContextStageChangedHunk.String():       review.ContextStageChangedHunk,
		review.ContextStageDirectReference.String():   review.ContextStageDirectReference,
		review.ContextStageRepositoryContext.String(): review.ContextStageRepositoryContext,
	}
	bound := func(id string, stage review.ContextStage, rangeValue evidence.SourceRange) review.ContextSource {
		content := f.contents[rangeValue.Path()]
		file, err := evidence.NewRepositoryFile(rangeValue.Path(), content)
		check(err)
		lines := bytes.SplitAfter(content, []byte("\n"))
		slice := bytes.Join(lines[rangeValue.StartLine()-1:rangeValue.EndLine()], nil)
		binding, err := evidence.BindSourceSlice(file, content, rangeValue, slice)
		check(err)
		if id == "" {
			id = binding.Identity()
		}
		item, err := evidence.NewEvidenceItem(id, evidence.EvidenceKindSource, binding.SliceDigest(), rangeValue)
		check(err)
		source, err := review.NewBoundContextSource(stage, memorycore.TaintRepositoryControlled, item, slice, binding)
		check(err)
		return source
	}
	var sources []review.ContextSource
	var ranges []evidence.SourceRange
	for _, recorded := range recordedBindingSources(t, f) {
		stage, ok := stages[recorded.Stage]
		if !ok {
			t.Fatalf("unexpected recorded stage %q", recorded.Stage)
		}
		rangeValue, err := evidence.NewSourceRange(recorded.Path, recorded.StartLine, recorded.EndLine)
		check(err)
		sources = append(sources, bound(recorded.SourceID, stage, rangeValue))
		ranges = append(ranges, rangeValue)
	}
	rangeValue, err := evidence.NewSourceRange(path, startLine, endLine)
	check(err)
	sources = append(sources, bound("", review.ContextStageRepositoryContext, rangeValue))
	ranges = append(ranges, rangeValue)
	return rebuildSourceBindingContext(t, f, sources, ranges)
}

// A base-branch instruction file that the head leaves byte-identical reaches
// the generation context as repository_context. Publication binds it to the
// exact head snapshot file and range, and refuses it as a published location.
func TestBuildSourceBindingBindsRepositoryInstructionContext(t *testing.T) {
	shared := map[string]string{"AGENTS.md": instructionBindingNotes}
	f := newSourceBindingFixtureWith(t, false, "package p\nfunc Changed() int{return 1}\n", "package p\nfunc Changed() int{return 2}\n", shared, shared)
	instruction := false
	for _, source := range recordedBindingSources(t, f) {
		instruction = instruction || source.Path == "AGENTS.md" && source.Stage == "repository_context" && source.StartLine == 1 && source.EndLine == 2
	}
	if !instruction || len(f.input.EvidenceItems()) != 2 {
		t.Fatalf("context lacks the repository_context instruction source: evidence=%d", len(f.input.EvidenceItems()))
	}
	assertExactProtectedBinding(t, f)
	handler := &Handler{store: f.store}
	changed, err := evidence.NewSourceRange("a.go", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler.buildSourceBinding(context.Background(), f.scope, f.target, []evidence.SourceRange{changed}, artifact.Artifact{}, f.inputArtifact, f.contextArtifact, time.UnixMilli(250)); err != nil {
		t.Fatalf("publication refused a changed-code location beside instruction context: %v", err)
	}
	for _, lines := range [][2]int{{1, 1}, {2, 2}} {
		location, err := evidence.NewSourceRange("AGENTS.md", lines[0], lines[1])
		if err != nil {
			t.Fatal(err)
		}
		binding, err := handler.buildSourceBinding(context.Background(), f.scope, f.target, []evidence.SourceRange{changed, location}, artifact.Artifact{}, f.inputArtifact, f.contextArtifact, time.UnixMilli(250))
		if err == nil || binding.Identity() != "" {
			t.Fatalf("publication accepted a finding located in instruction context at %v", lines)
		}
	}
}

func TestBuildSourceBindingRefusesUnauthorizedInstructionContext(t *testing.T) {
	cases := []struct {
		name             string
		base, head       map[string]string
		path             string
		startLine, lines int
	}{
		// The head edits line 2, so line 1 is an unchanged prefix of a file
		// whose base copy differs.
		{"head_changed", map[string]string{"AGENTS.md": "Same.\nBase.\n"}, map[string]string{"AGENTS.md": "Same.\nHead.\n"}, "AGENTS.md", 1, 1},
		{"head_only", nil, map[string]string{"AGENTS.md": "Head notes.\nMore.\n"}, "AGENTS.md", 1, 1},
		{"not_instruction_path", map[string]string{"README.md": "Read me.\n"}, map[string]string{"README.md": "Read me.\n"}, "README.md", 1, 1},
		{"nested_instruction_path", map[string]string{"docs/AGENTS.md": "Nested.\n"}, map[string]string{"docs/AGENTS.md": "Nested.\n"}, "docs/AGENTS.md", 1, 1},
		{"not_a_prefix", map[string]string{"AGENTS.md": instructionBindingNotes}, map[string]string{"AGENTS.md": instructionBindingNotes}, "AGENTS.md", 2, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newSourceBindingFixtureWith(t, false, "package p\nfunc Changed() int{return 1}\n", "package p\nfunc Changed() int{return 2}\n", c.base, c.head)
			for _, source := range recordedBindingSources(t, f) {
				exact := source.Path == c.path && source.StartLine == c.startLine && source.EndLine == c.lines
				if exact || source.Path == c.path && source.Stage == "repository_context" && c.name != "not_a_prefix" {
					t.Fatalf("context assembly already supplied %s as %s", c.path, source.Stage)
				}
			}
			f = withForgedInstructionSource(t, f, c.path, c.startLine, c.lines)
			handler := &Handler{store: f.store}
			binding, err := handler.buildSourceBinding(context.Background(), f.scope, f.target, nil, artifact.Artifact{}, f.inputArtifact, f.contextArtifact, time.UnixMilli(250))
			if err == nil || binding.Identity() != "" {
				t.Fatal("publication bound repository_context evidence outside base instruction authority")
			}
		})
	}
}
