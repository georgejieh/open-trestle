package analysiscodec

import (
	"bytes"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

// deletionContextAnalysis builds a version 6 result for "guard\nkeep\n" ->
// "keep\n": one context item over head line 1 and a deleted_lines gap at the
// deletion point (head line 1, the first line after the removed one).
func deletionContextAnalysis(t *testing.T) (artifact.Artifact, artifact.Artifact, artifact.Artifact, artifact.Artifact, Result, changecodec.Entry) {
	t.Helper()
	change, base, head := deletionChange(t, "guard\nkeep\n", "keep\n")
	payload, err := changecodec.EncodeResult(change)
	if err != nil {
		t.Fatal(err)
	}
	changeArtifact, err := artifact.New(base.Scope(), artifact.KindChangeModel, "application/json", base.Classification(), artifact.OriginDeterministicTool, base.Protection(), []string{base.Identity(), head.Identity()}, payload, time.UnixMilli(200), base.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	change, err = changecodec.ParseResultArtifact(changeArtifact, base, head)
	if err != nil {
		t.Fatal(err)
	}
	headSnapshot, err := sourceoutput.ParseSnapshotArtifact(head)
	if err != nil {
		t.Fatal(err)
	}
	entry := change.Entries()[0]
	content := []byte("keep\n")
	file, _ := evidence.NewRepositoryFile("a.txt", content)
	sourceRange, _ := evidence.NewSourceRange("a.txt", 1, 1)
	binding, err := evidence.BindSourceSlice(file, content, sourceRange, content)
	if err != nil {
		t.Fatal(err)
	}
	item, err := NewDeletionContextItem(entry, binding)
	if err != nil {
		t.Fatal(err)
	}
	input, _ := semanticimpact.NewInput(change.BaseSnapshotIdentity(), change.HeadSnapshotIdentity(), change.Identity(), nil, nil, nil)
	profile, err := semanticimpact.AnalyzeGo(input)
	if err != nil {
		t.Fatal(err)
	}
	check, _ := NewDeterministicCheck(change.Identity(), CheckNotApplicable, 0, 0, 0, 0, 0)
	result, err := NewResult(changeArtifact, change, head, headSnapshot, []Item{item}, []Gap{NewGap(entry, 1, 1, DeletionContextReason)}, []DeterministicCheck{check}, nil, profile)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	output, err := artifact.New(base.Scope(), artifact.KindDeterministicEvidence, "application/json", base.Classification(), artifact.OriginDeterministicTool, base.Protection(), []string{changeArtifact.Identity(), change.Identity(), head.Identity(), change.HeadSnapshotIdentity()}, payload, time.UnixMilli(300), base.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	return output, changeArtifact, base, head, result, entry
}

func TestDeletionContextIsVersionSixAndRoundTrips(t *testing.T) {
	output, changeArtifact, base, head, _, _ := deletionContextAnalysis(t)
	parsed, err := ParseResultArtifact(output, changeArtifact, base, head)
	if err != nil || parsed.SchemaVersion() != 6 || len(parsed.Items()) != 1 || len(parsed.Gaps()) != 1 || parsed.changedRanges != 0 {
		t.Fatalf("parse=%#v err=%v", parsed, err)
	}
	if gap := parsed.Gaps()[0]; gap.Reason() != DeletionContextReason || gap.StartLine() != 1 || gap.EndLine() != 1 {
		t.Fatalf("deletion point gap=%#v", gap)
	}
	if item := parsed.Items()[0]; item.Path() != "a.txt" || item.StartLine() != 1 || item.EndLine() != 1 {
		t.Fatalf("deletion context item=%#v", item)
	}
	encoded, err := EncodeResult(parsed)
	if err != nil || !bytes.Equal(encoded, output.Payload()) {
		t.Fatalf("v6 round trip changed bytes: %v", err)
	}
}

func TestDeletionContextRejectsTampering(t *testing.T) {
	output, changeArtifact, base, head, result, entry := deletionContextAnalysis(t)
	for _, tc := range []struct {
		name   string
		mutate func(*Result)
	}{
		{"context item at version 5", func(r *Result) { r.schemaVersion = 5 }},
		{"context item without deletion point", func(r *Result) { r.gaps = nil }},
		{"deletion point without context item", func(r *Result) { r.items = nil }},
		{"context item beside whole-entry gap", func(r *Result) { r.gaps = append(r.gaps, NewGap(entry, 0, 0, "no_changed_head_lines")) }},
		{"deletion point with zero coordinates", func(r *Result) { r.gaps[0].startLine, r.gaps[0].endLine = 0, 0 }},
		{"inverted deletion point", func(r *Result) { r.gaps[0].startLine, r.gaps[0].endLine = 2, 1 }},
		{"forged item binding", func(r *Result) { r.items[0].bindingIdentity = r.items[0].digest }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rejectResult(t, output, changeArtifact, base, head, canonicalMutation(t, result, tc.mutate))
		})
	}
}

func TestDeletionContextItemRequiresDeletionOnlyEntry(t *testing.T) {
	change, _, _ := deletionChange(t, "guard\nkeep\n", "keep\n")
	entry := change.Entries()[0]
	content := []byte("other\n")
	file, _ := evidence.NewRepositoryFile("a.txt", content)
	sourceRange, _ := evidence.NewSourceRange("a.txt", 1, 1)
	binding, err := evidence.BindSourceSlice(file, content, sourceRange, content)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDeletionContextItem(entry, binding); err == nil {
		t.Fatal("context item bound to a different head file")
	}
}
