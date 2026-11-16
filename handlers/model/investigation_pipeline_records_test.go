package model

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
)

type analysisRecordStub struct {
	evidence, binding, file string
	headLine                int
}

func (r analysisRecordStub) EvidenceID() string      { return r.evidence }
func (r analysisRecordStub) BindingIdentity() string { return r.binding }
func (r analysisRecordStub) FileIdentity() string    { return r.file }
func (r analysisRecordStub) HeadLine() int           { return r.headLine }

func recordOf(source review.ContextSource) analysisRecordStub {
	return analysisRecordStub{source.ReferenceID(), source.SliceBindingIdentity(), source.SliceBinding().RepositoryFileIdentity(), source.HeadLine()}
}

// At assembly every removed_lines source must be exactly a removed-lines
// record of the analysis: same evidence, binding, base file and head line.
func TestInvestigationAssemblyMatchesRemovedLinesToTheirAnalysisRecord(t *testing.T) {
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
	sources := []review.ContextSource{window, removed}
	items, records := []analysisRecord{recordOf(window)}, []analysisRecord{recordOf(removed)}
	if !sourcesMatchAnalysis(sources, items, records) {
		t.Fatal("matching analysis records refused")
	}
	other := recordOf(removed)
	for name, record := range map[string]analysisRecordStub{
		"no record":       {},
		"other base file": {other.evidence, other.binding, strings.Repeat("f", 64), other.headLine},
		"other head line": {other.evidence, other.binding, other.file, 4},
		"other binding":   {other.evidence, strings.Repeat("e", 64), other.file, other.headLine},
	} {
		if sourcesMatchAnalysis(sources, items, []analysisRecord{record}) {
			t.Fatalf("%s: removed_lines source matched a foreign analysis record", name)
		}
	}
	// A removed_lines source is never matched against head evidence records.
	if sourcesMatchAnalysis(sources, append(items, recordOf(removed)), nil) {
		t.Fatal("removed_lines source matched a head evidence record")
	}
}
