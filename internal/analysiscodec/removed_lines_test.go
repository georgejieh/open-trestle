package analysiscodec

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

// removedLinesAnalysis builds a version 7 result for "guard\nkeep\n" ->
// "keep\n": deletion-point context over head line 1, a deleted_lines gap, and
// the removed base line 1 ("guard\n") bound to the exact base file. With limit
// set, the removed line is recorded as a removed_lines_limit gap instead.
func removedLinesAnalysis(t *testing.T, limit bool) (artifact.Artifact, artifact.Artifact, artifact.Artifact, artifact.Artifact, Result, changecodec.Entry) {
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
	headContent := []byte("keep\n")
	headFile, _ := evidence.NewRepositoryFile("a.txt", headContent)
	headRange, _ := evidence.NewSourceRange("a.txt", 1, 1)
	headBinding, err := evidence.BindSourceSlice(headFile, headContent, headRange, headContent)
	if err != nil {
		t.Fatal(err)
	}
	item, err := NewDeletionContextItem(entry, headBinding)
	if err != nil {
		t.Fatal(err)
	}
	baseContent := []byte("guard\nkeep\n")
	baseFile, _ := evidence.NewRepositoryFile("a.txt", baseContent)
	baseRange, _ := evidence.NewSourceRange("a.txt", 1, 1)
	baseBinding, err := evidence.BindSourceSlice(baseFile, baseContent, baseRange, []byte("guard\n"))
	if err != nil {
		t.Fatal(err)
	}
	gaps := []Gap{NewGap(entry, 1, 1, DeletionContextReason)}
	var removed []Item
	if limit {
		gaps = append(gaps, NewGap(entry, 1, 1, RemovedLinesLimitReason))
	} else {
		value, err := NewRemovedLinesItem(entry, baseBinding, 1)
		if err != nil {
			t.Fatal(err)
		}
		removed = []Item{value}
	}
	input, _ := semanticimpact.NewInput(change.BaseSnapshotIdentity(), change.HeadSnapshotIdentity(), change.Identity(), nil, nil, nil)
	profile, err := semanticimpact.AnalyzeGo(input)
	if err != nil {
		t.Fatal(err)
	}
	check, _ := NewDeterministicCheck(change.Identity(), CheckNotApplicable, 0, 0, 0, 0, 0)
	result, err := NewResultWithRemovedLines(changeArtifact, change, head, headSnapshot, []Item{item}, removed, gaps, []DeterministicCheck{check}, nil, profile)
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

func TestRemovedLinesAreVersionSevenAndRoundTrip(t *testing.T) {
	for _, limit := range []bool{false, true} {
		output, changeArtifact, base, head, _, _ := removedLinesAnalysis(t, limit)
		parsed, err := ParseResultArtifact(output, changeArtifact, base, head)
		if err != nil || parsed.SchemaVersion() != 7 || len(parsed.Items()) != 1 {
			t.Fatalf("limit=%v parse=%#v err=%v", limit, parsed, err)
		}
		if limit {
			if len(parsed.RemovedLines()) != 0 || len(parsed.Gaps()) != 2 || parsed.Gaps()[1].Reason() != RemovedLinesLimitReason || parsed.Gaps()[1].StartLine() != 1 {
				t.Fatalf("limit gaps=%#v removed=%d", parsed.Gaps(), len(parsed.RemovedLines()))
			}
			if !bytes.Contains(output.Payload(), []byte(`"removed_lines":[]`)) {
				t.Fatal("version 7 omitted an empty removed_lines array")
			}
		} else {
			removed := parsed.RemovedLines()
			baseFile, _ := evidence.NewRepositoryFile("a.txt", []byte("guard\nkeep\n"))
			if len(removed) != 1 || removed[0].StartLine() != 1 || removed[0].EndLine() != 1 || removed[0].FileDigest() != baseFile.Digest() || removed[0].FileIdentity() != baseFile.Identity() {
				t.Fatalf("removed=%#v", removed)
			}
			evidenceItem, err := removed[0].EvidenceItem()
			if err != nil || evidenceItem.ID() != removed[0].BindingIdentity() {
				t.Fatalf("removed evidence item: %v", err)
			}
		}
		encoded, err := EncodeResult(parsed)
		if err != nil || !bytes.Equal(encoded, output.Payload()) {
			t.Fatalf("v7 round trip changed bytes: %v", err)
		}
	}
}

func TestRemovedLinesRejectTampering(t *testing.T) {
	output, changeArtifact, base, head, result, entry := removedLinesAnalysis(t, false)
	other, _ := evidence.NewRepositoryFile("a.txt", []byte("other\nkeep\n"))
	for _, tc := range []struct {
		name   string
		mutate func(*Result)
	}{
		{"removed text at version 6", func(r *Result) { r.schemaVersion = 6 }},
		{"version 7 without removed text", func(r *Result) { r.removed = nil }},
		{"removed text without deletion context", func(r *Result) { r.items = nil }},
		{"removed text without deletion point", func(r *Result) { r.gaps = nil }},
		{"removed text bound to the head file", func(r *Result) {
			r.removed[0].fileDigest, r.removed[0].fileIdentity = r.items[0].fileDigest, r.items[0].fileIdentity
			r.removed[0].bindingIdentity = deriveBindingIdentity(r.removed[0])
			r.removed[0].evidenceID = r.removed[0].bindingIdentity
		}},
		{"removed text bound to another base file", func(r *Result) {
			r.removed[0].fileDigest, r.removed[0].fileIdentity = other.Digest(), other.Identity()
			r.removed[0].bindingIdentity = deriveBindingIdentity(r.removed[0])
			r.removed[0].evidenceID = r.removed[0].bindingIdentity
		}},
		{"forged removed binding", func(r *Result) { r.removed[0].bindingIdentity = r.removed[0].digest }},
		{"removed text overlapping a limit gap", func(r *Result) { r.gaps = append(r.gaps, NewGap(entry, 1, 1, RemovedLinesLimitReason)) }},
		{"duplicate removed text", func(r *Result) { r.removed = append(r.removed, r.removed[0]) }},
		{"removed text beside whole-entry gap", func(r *Result) { r.gaps = append(r.gaps, NewGap(entry, 0, 0, "no_changed_head_lines")) }},
		{"removed text without a head line", func(r *Result) { r.removed[0].headLine = 0 }},
		{"removed text naming another deletion point", func(r *Result) { r.removed[0].headLine = 2 }},
		{"head line on deletion-point context", func(r *Result) { r.items[0].headLine = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rejectResult(t, output, changeArtifact, base, head, canonicalMutation(t, result, tc.mutate))
		})
	}
	limitOutput, _, _, _, limitResult, limitEntry := removedLinesAnalysis(t, true)
	for _, tc := range []struct {
		name   string
		mutate func(*Result)
	}{
		{"limit gap at version 6", func(r *Result) { r.schemaVersion = 6 }},
		{"limit gap without coordinates", func(r *Result) { r.gaps[1].startLine, r.gaps[1].endLine = 0, 0 }},
		{"limit gap without deletion context", func(r *Result) { r.items = nil }},
		{"overlapping limit gaps", func(r *Result) { r.gaps = append(r.gaps, NewGap(limitEntry, 1, 2, RemovedLinesLimitReason)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rejectResult(t, limitOutput, changeArtifact, base, head, canonicalMutation(t, limitResult, tc.mutate))
		})
	}
	if _, err := NewRemovedLinesItem(entry, func() evidence.SourceSliceBinding {
		content := []byte("keep\n")
		file, _ := evidence.NewRepositoryFile("a.txt", content)
		sourceRange, _ := evidence.NewSourceRange("a.txt", 1, 1)
		binding, _ := evidence.BindSourceSlice(file, content, sourceRange, content)
		return binding
	}(), 1); err == nil {
		t.Fatal("removed-lines item bound to the head file")
	}
	// Version 6 bytes stay readable and never gain removed_lines.
	v6Output, v6Change, v6Base, v6Head, _, _ := deletionContextAnalysis(t)
	parsed, err := ParseResultArtifact(v6Output, v6Change, v6Base, v6Head)
	if err != nil || parsed.SchemaVersion() != 6 || len(parsed.RemovedLines()) != 0 || strings.Contains(string(v6Output.Payload()), "removed_lines") {
		t.Fatalf("v6 readback: version=%d err=%v", parsed.SchemaVersion(), err)
	}
	withRemoved := wireMutation(t, v6Output.Payload(), func(w *resultWire) { w.RemovedLines = itemWireValues(result.removed) }, true)
	rejectResult(t, v6Output, v6Change, v6Base, v6Head, withRemoved)
}
