package review

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
)

func contextSourceForSelection(t *testing.T, id, path, content string, stage ContextStage) ContextSource {
	t.Helper()
	lineCount := strings.Count(content, "\n")
	if !strings.HasSuffix(content, "\n") {
		lineCount++
	}
	sourceRange, err := evidence.NewSourceRange(path, 1, lineCount)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(content))
	item, err := evidence.NewEvidenceItem(id, evidence.EvidenceKindSource, hex.EncodeToString(digest[:]), sourceRange)
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewContextSource(stage, memory.TaintRepositoryControlled, item, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func TestSelectContextSourcesAccountsForEveryCandidate(t *testing.T) {
	first := contextSourceForSelection(t, "source-a", "internal/a.go", "aaaa", ContextStageChangedHunk)
	second := contextSourceForSelection(t, "source-b", "internal/b.go", "bbbb", ContextStageEnclosingSymbol)
	third := contextSourceForSelection(t, "source-c", "internal/c.go", "c", ContextStageDirectReference)
	limits, _ := NewContextLimits(5, 0)
	selection, err := SelectContextSources([]ContextSource{third, second, first}, limits)
	if err != nil {
		t.Fatal(err)
	}
	entries := selection.Entries()
	if selection.Identity() == "" || selection.CandidateCount() != 3 || selection.SelectedCount() != 2 || selection.OmittedCount() != 1 || selection.SelectedBytes() != 5 || selection.Validate() != nil || len(entries) != 3 {
		t.Fatalf("selection did not round trip: %#v", selection)
	}
	if !entries[0].Selected() || entries[0].ReferenceID() != "source-a" || entries[0].Reason() != ContextSourceSelected || entries[1].Selected() || entries[1].Reason() != ContextSourceOmittedByteLimit || !entries[2].Selected() || entries[2].ReferenceID() != "source-c" {
		t.Fatalf("unexpected decisions: %#v", entries)
	}
	selected := selection.SelectedSources()
	if len(selected) != 2 || selected[0].ReferenceID() != "source-a" || selected[1].ReferenceID() != "source-c" {
		t.Fatalf("selected sources = %#v", selected)
	}
	entries[0] = ContextSourceSelectionEntry{}
	selected[0] = ContextSource{}
	if selection.Entries()[0].ReferenceID() != "source-a" || selection.SelectedSources()[0].ReferenceID() != "source-a" {
		t.Fatal("selection exposed mutable slices")
	}
	if fmt.Sprint(selection) != "review context source selection" || strings.Contains(fmt.Sprintf("%v", selection), "source-a") {
		t.Fatalf("selection formatting leaked: %v", selection)
	}
}

func TestSelectContextSourcesIsOrderIndependent(t *testing.T) {
	first := contextSourceForSelection(t, "source-a", "internal/a.go", "a", ContextStageChangedHunk)
	second := contextSourceForSelection(t, "source-b", "internal/b.go", "b", ContextStageDirectReference)
	limits, _ := NewContextLimits(10, 0)
	ordered, _ := SelectContextSources([]ContextSource{first, second}, limits)
	reversed, _ := SelectContextSources([]ContextSource{second, first}, limits)
	if ordered.Identity() != reversed.Identity() || !reflect.DeepEqual(ordered.SourceIdentities(), reversed.SourceIdentities()) {
		t.Fatal("equivalent source sets produced different selections")
	}
}

func TestSelectContextSourcesRecordsCountOmissions(t *testing.T) {
	sources := make([]ContextSource, maxSelectedContextSources+1)
	for index := range sources {
		id := fmt.Sprintf("source-%02d", index)
		path := fmt.Sprintf("internal/%02d.go", index)
		sources[index] = contextSourceForSelection(t, id, path, "x", ContextStageRepositoryContext)
	}
	limits, _ := NewContextLimits(1<<20, 0)
	selection, err := SelectContextSources(sources, limits)
	if err != nil {
		t.Fatal(err)
	}
	entries := selection.Entries()
	if selection.SelectedCount() != maxSelectedContextSources || selection.OmittedCount() != 1 || entries[len(entries)-1].Reason() != ContextSourceOmittedCountLimit {
		t.Fatalf("count decisions = %#v", selection)
	}
}

func TestSelectContextSourcesRejectsDuplicateAndExcessiveCandidates(t *testing.T) {
	source := contextSourceForSelection(t, "source-a", "internal/a.go", "a", ContextStageChangedHunk)
	limits, _ := NewContextLimits(10, 0)
	if selection, err := SelectContextSources([]ContextSource{source, source}, limits); !errors.Is(err, ErrDuplicateContextSource) || selection.Identity() != "" {
		t.Fatalf("duplicate selection = (%#v, %v)", selection, err)
	}
	tooMany := make([]ContextSource, maxContextSourceCandidates+1)
	if selection, err := SelectContextSources(tooMany, limits); !errors.Is(err, ErrInvalidContextSource) || selection.Identity() != "" {
		t.Fatalf("excessive selection = (%#v, %v)", selection, err)
	}
	selection, _ := SelectContextSources([]ContextSource{source}, limits)
	forged := selection
	forged.identity = strings.Repeat("f", 64)
	if !errors.Is(forged.Validate(), ErrInvalidContextSourceSelectionIdentity) {
		t.Fatal("forged selection accepted")
	}
}

func TestContextSourceSelectionReasonRoundTrips(t *testing.T) {
	for _, token := range []string{"selected", "omitted_byte_limit", "omitted_count_limit"} {
		reason, err := ParseContextSourceSelectionReason(token)
		if err != nil || reason.String() != token || reason.Validate() != nil {
			t.Fatalf("reason %q = (%v, %v)", token, reason, err)
		}
	}
}
