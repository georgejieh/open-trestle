package context

import (
	"bytes"
	"strings"
	"testing"
)

// Removing a guard changes no head line, so the head lines around the deletion
// point enter the packet as a changed_hunk source and the deletion point is a
// labelled omission.
func TestDeletionOnlyChangeIsReviewableFromDeletionPointContext(t *testing.T) {
	base := map[string][]byte{"calc.go": []byte("package calc\n\nfunc Div(a, b int) int {\n\tif b == 0 {\n\t\treturn 0\n\t}\n\treturn a / b\n}\n")}
	head := map[string][]byte{"calc.go": []byte("package calc\n\nfunc Div(a, b int) int {\n\treturn a / b\n}\n")}
	result := assembleTextFallback(t, base, head)
	if result.failure != 0 || result.abstention != nil {
		t.Fatalf("deletion-only change refused: failure=%s abstention=%v", result.failure, result.abstention != nil)
	}
	source, ok := result.sources["calc.go|changed_hunk"]
	if !ok {
		t.Fatalf("no changed_hunk source for the deletion point: %v", result.sources)
	}
	rangeValue := source.EvidenceItem().SourceRange()
	if rangeValue.StartLine() != 1 || rangeValue.EndLine() != 5 || !bytes.Contains(source.Content(), []byte("return a / b")) {
		t.Fatalf("deletion context %d-%d %q", rangeValue.StartLine(), rangeValue.EndLine(), source.Content())
	}
	if bytes.Contains(source.Content(), []byte("b == 0")) {
		t.Fatal("removed base text entered the packet as head source")
	}
	found := false
	for _, omission := range result.assembly.Packet.SourceOmissions() {
		if omission.Path() == "calc.go" && omission.Reason() == "analysis_deleted_lines" && omission.StartLine() == 3 && omission.EndLine() == 4 {
			found = true
		}
		if omission.Reason() == "analysis_no_changed_head_lines" {
			t.Fatal("whole-entry omission recorded although deletion context was built")
		}
	}
	if !found {
		t.Fatalf("deletion point omission missing: %v", result.omissionSet)
	}
}

// Removed text past the analysis bound reaches the packet as an explicit
// analysis_removed_lines_limit omission at its base range, counted with the
// resource-limit omissions; the change stays reviewable from its head context.
func TestRemovedLinesPastTheBoundAreAnExplicitOmission(t *testing.T) {
	removed := strings.Repeat("dropped line\n", 70)
	base := map[string][]byte{"a.txt": []byte("keep one\n" + removed + "keep two\n")}
	head := map[string][]byte{"a.txt": []byte("keep one\nkeep two\n")}
	result := assembleTextFallback(t, base, head)
	if result.failure != 0 || result.abstention != nil {
		t.Fatalf("deletion-only change refused: failure=%s abstention=%v", result.failure, result.abstention != nil)
	}
	found := false
	for _, omission := range result.assembly.Packet.SourceOmissions() {
		if omission.Path() == "a.txt" && omission.Reason() == "analysis_removed_lines_limit" && omission.StartLine() == 2 && omission.EndLine() == 71 {
			found = true
		}
	}
	if !found {
		t.Fatalf("removed-lines limit omission missing: %v", result.omissionSet)
	}
}

// An emptied head file has no head line beside the deletion: it is reviewed
// from its removed text alone, keeps its whole-entry omission, and gains no
// invented head source.
func TestDeletionToEmptyFileIsReviewedFromItsRemovedText(t *testing.T) {
	result := assembleTextFallback(t, map[string][]byte{"a.txt": []byte("gone\n")}, map[string][]byte{"a.txt": []byte("")})
	if result.abstention != nil || result.failure != 0 {
		t.Fatalf("emptied file refused: failure=%s", result.failure)
	}
	removed, ok := result.sources["a.txt|removed_lines"]
	if !ok || string(removed.Content()) != "gone\n" || removed.HeadLine() != 0 || len(result.sources) != 1 {
		t.Fatalf("sources=%v", result.sources)
	}
	if !result.omissionSet["a.txt|analysis_no_changed_head_lines"] || len(result.assembly.Snapshot.Ranges()) != 0 {
		t.Fatalf("emptied file lost its whole-entry omission or gained a head range: %v", result.omissionSet)
	}
}
