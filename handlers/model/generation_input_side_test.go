package model

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
)

func boundGenerationSource(t *testing.T, path, content string, start, end int) (evidence.EvidenceItem, evidence.SourceSliceBinding) {
	t.Helper()
	file, err := evidence.NewRepositoryFile(path, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	span, _ := evidence.NewSourceRange(path, start, end)
	binding, err := evidence.BindSourceRange(file, []byte(content), span)
	if err != nil {
		t.Fatal(err)
	}
	item, err := evidence.NewEvidenceItem(binding.Identity(), evidence.EvidenceKindSource, binding.SliceDigest(), span)
	if err != nil {
		t.Fatal(err)
	}
	return item, binding
}

// baseEvidenceGenerationInput builds an unsanitized generation input that
// cites removed text: a deletion point's removed lines beside its head window
// and a removed file's text. With wholeFileOnly the change only removes the
// file, so the snapshot has no head range and the removed file is the only
// evidence.
func baseEvidenceGenerationInput(t *testing.T, wholeFileOnly bool) GenerationInput {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	memoryScope, _ := memory.NewScope("tenant-a", "repo-a", "actor-a", memory.RefVisibilityExact, strings.Repeat("a", 64), []string{"src"})
	head := "package calc\n\nfunc Div(a, b int) int {\n\treturn a / b\n}\n"
	base := "package calc\n\nfunc Div(a, b int) int {\n\tif b == 0 {\n\t\treturn 0\n\t}\n\treturn a / b\n}\n"
	windowItem, windowBinding := boundGenerationSource(t, "src/calc.go", head, 1, 5)
	window, err := review.NewBoundContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, windowItem, []byte(strings.Join(strings.SplitAfter(head, "\n")[0:5], "")), windowBinding)
	if err != nil {
		t.Fatal(err)
	}
	removedItem, removedBinding := boundGenerationSource(t, "src/calc.go", base, 4, 6)
	removed, err := review.NewRemovedLinesContextSource(removedItem, []byte("\tif b == 0 {\n\t\treturn 0\n\t}\n"), removedBinding, 3)
	if err != nil {
		t.Fatal(err)
	}
	gone, goneBinding := boundGenerationSource(t, "src/gone.go", "package gone\n", 1, 1)
	removedFile, err := review.NewRemovedLinesContextSource(gone, []byte("package gone\n"), goneBinding, 0)
	if err != nil {
		t.Fatal(err)
	}
	ranges, sources := []evidence.SourceRange{windowItem.SourceRange()}, []review.ContextSource{window, removed, removedFile}
	if wholeFileOnly {
		ranges, sources = nil, []review.ContextSource{removedFile}
	}
	snapshot, _ := review.NewReviewSnapshot("workspace", strings.Repeat("b", 64), ranges)
	query, _ := memory.NewLexicalQuery(memoryScope, "src/calc.go", nil, nil, time.UnixMilli(100), 5)
	retrieval, err := memory.NewLexicalIndex().Search(context.Background(), memoryScope, query)
	if err != nil {
		t.Fatal(err)
	}
	limits, _ := review.NewContextLimits(1<<20, 0)
	packet, err := review.NewContextPacket(scope, memoryScope, snapshot, review.ContextTaskCandidateGeneration, sources, retrieval, limits)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := packet.ProviderRequest()
	contextArtifact, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{strings.Repeat("e", 64)}, request.Payload(), time.UnixMilli(50), time.UnixMilli(10000))
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewGenerationInput(contextArtifact, packet, snapshot, generationAuthorization(t, scope, request))
	if err != nil {
		t.Fatalf("generation input refused removed_lines evidence: %v", err)
	}
	return input
}

// A generation input admits evidence outside the head snapshot only for a
// removed_lines source, whose lines are base lines, and records which items
// those are.
func TestGenerationInputAdmitsOnlyRemovedLinesOutsideTheSnapshot(t *testing.T) {
	input := baseEvidenceGenerationInput(t, false)
	encoded, err := EncodeGenerationInput(input)
	if err != nil || !bytes.Contains(encoded, []byte(`"schema_version":4`)) || bytes.Count(encoded, []byte(`"side":"base"`)) != 2 {
		t.Fatalf("encoded input: %s, %v", encoded, err)
	}
	if parsed, err := ParseGenerationInput(encoded); err != nil || parsed.Identity() != input.Identity() {
		t.Fatalf("version 4 input does not read back: %v", err)
	}
	// Recorded as head evidence, an item outside the snapshot is refused,
	// even on a path the snapshot covers.
	for name, forged := range map[string][]byte{
		"removed file as head evidence": bytes.Replace(encoded, []byte(`"end_line":1,"side":"base"`), []byte(`"end_line":1`), 1),
		"version 1 with a side":         bytes.Replace(encoded, []byte(`"schema_version":4`), []byte(`"schema_version":1`), 1),
	} {
		if bytes.Equal(forged, encoded) {
			t.Fatalf("%s: forgery did not change the bytes", name)
		}
		if _, err := ParseGenerationInput(forged); err == nil {
			t.Fatalf("%s read back", name)
		}
	}
	// A head-only input keeps version 1.
	headScope, headSnapshot, headPacket, headArtifact, headRequest := generationContextFixture(t)
	headInput, err := NewGenerationInput(headArtifact, headPacket, headSnapshot, generationAuthorization(t, headScope, headRequest))
	if err != nil {
		t.Fatal(err)
	}
	if encoded, err := EncodeGenerationInput(headInput); err != nil || !bytes.Contains(encoded, []byte(`"schema_version":1`)) || bytes.Contains(encoded, []byte(`"side"`)) {
		t.Fatalf("head-only input changed version: %s", encoded)
	}
}
