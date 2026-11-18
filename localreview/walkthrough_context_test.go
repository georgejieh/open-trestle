package localreview

import (
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/review"
)

func contextFixtureManifest() review.ContextManifestSummary {
	return review.ContextManifestSummary{
		Present: true, State: review.ContextIndexUsed, Complete: true,
		Budget: review.ContextBudget{Basis: review.ContextBudgetRouteWindow, RouteContextTokens: 64000, OutputTokens: 4096, MaxSourceBytes: 29 << 10, MaxSources: 32},
		Included: []review.ContextManifestSummarySource{
			{SourceID: "s1", Path: "calc/div.go", Stage: review.ContextStageEnclosingSymbol, StartLine: 3, EndLine: 6, Rank: 1},
			{SourceID: "s2", Path: "calc/half.go", Stage: review.ContextStageDirectReference, StartLine: 4, EndLine: 6, Rank: 1, Depth: 1},
			{SourceID: "s3", Path: "calc/div_test.go", Stage: review.ContextStageRelatedTest, StartLine: 5, EndLine: 9, Rank: 1, Depth: 1},
			{SourceID: "s4", Path: "tools/scale.py", Stage: review.ContextStageRepositoryMap, StartLine: 1, EndLine: 1, Rank: 1},
		},
		Omitted:    []review.ContextManifestOmission{{Stage: review.ContextStageDirectReference, Reason: review.ContextOmittedStageLimit, Count: 3}, {Stage: review.ContextStageRepositoryMap, Reason: review.ContextOmittedPacketBudget, Count: 1}},
		Changed:    []review.ContextManifestSummaryDefinition{{Path: "calc/div.go", Line: 3, Dependents: 2, Tests: 1}},
		Dependents: 2,
		Checks:     []string{"lint", "unit_tests"},
	}
}

func TestContextWalkthroughCountsIncludedSourcesByStage(t *testing.T) {
	if contextWalkthrough(review.ContextManifestSummary{}) != nil || !(*WalkthroughContext)(nil).valid() {
		t.Fatal("a context without a manifest is not absent")
	}
	w := contextWalkthrough(contextFixtureManifest())
	if w == nil || !w.valid() {
		t.Fatalf("walkthrough context = %+v", w)
	}
	if w.Index != "used" || !w.Complete || w.Budget != "route_window" || w.MaxSourceBytes != 29<<10 || w.MaxSources != 32 || w.RouteContextTokens != 64000 {
		t.Fatalf("index and budget = %+v", w)
	}
	if w.Definitions != 1 || w.Callers != 1 || w.Tests != 1 || w.MapEntries != 1 || len(w.Included) != 4 || w.Included[1] != (WalkthroughContextSource{Stage: "direct_reference", Path: "calc/half.go", StartLine: 4, EndLine: 6, Rank: 1, Depth: 1}) {
		t.Fatalf("included = %+v", w)
	}
	if !reflect.DeepEqual(w.Omitted, []WalkthroughContextOmitted{{"direct_reference", "stage_limit", 3}, {"repository_map", "packet_budget", 1}}) || !reflect.DeepEqual(w.Checks, []string{"lint", "unit_tests"}) {
		t.Fatalf("omitted = %+v checks = %v", w.Omitted, w.Checks)
	}
	copied := w.clone()
	copied.Included[0].Path, copied.Omitted[0].Count, copied.Checks[0] = "other.go", 9, "formatting"
	if w.Included[0].Path != "calc/div.go" || w.Omitted[0].Count != 3 || w.Checks[0] != "lint" {
		t.Fatal("a clone shares its lists with the original")
	}
	if (*WalkthroughContext)(nil).clone() != nil {
		t.Fatal("the clone of no context is not none")
	}
}

func TestContextWalkthroughValidationRefusesInconsistentRecords(t *testing.T) {
	for name, mutate := range map[string]func(*WalkthroughContext){
		"stage count above the list": func(w *WalkthroughContext) { w.Callers++ },
		"unknown index state":        func(w *WalkthroughContext) { w.Index = "ready" },
		"unknown budget basis":       func(w *WalkthroughContext) { w.Budget = "guess" },
		"unknown check class":        func(w *WalkthroughContext) { w.Checks = []string{"everything"} },
		"empty source path":          func(w *WalkthroughContext) { w.Included[0].Path = "" },
		"source line before one":     func(w *WalkthroughContext) { w.Included[0].StartLine = 0 },
		"zero omission count":        func(w *WalkthroughContext) { w.Omitted[0].Count = 0 },
		"missing source list":        func(w *WalkthroughContext) { w.Included = nil },
	} {
		w := contextWalkthrough(contextFixtureManifest())
		mutate(w)
		if w.valid() {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestContextTextWordsTheIndexStateBudgetAndChecks(t *testing.T) {
	if contextText(nil) != nil {
		t.Fatal("no context printed a line")
	}
	lines := contextText(contextWalkthrough(contextFixtureManifest()))
	want := []string{
		"context used: 1 enclosing definition, 1 caller, 1 test, 1 map entry; left out: 3 callers (stage limit), 1 map entry (packet budget); budget 29 KiB in 32 sources (route window)",
		"checks the repository already enforces: lint, unit_tests",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("lines = %q", lines)
	}
	incomplete := contextFixtureManifest()
	incomplete.Complete, incomplete.Omitted, incomplete.Checks = false, nil, nil
	if lines := contextText(contextWalkthrough(incomplete)); len(lines) != 1 || !strings.Contains(lines[0], "(the index does not cover every file)") || strings.Contains(lines[0], "left out") {
		t.Fatalf("incomplete index lines = %q", lines)
	}
	for state, fragment := range map[string]string{
		review.ContextIndexUnavailable: "changed code only (no repository index)",
		review.ContextIndexOverBudget:  "changed code only (the repository index was not ready within its time budget)",
		review.ContextIndexFailed:      "changed code only (the repository index could not be read)",
	} {
		manifest := review.ContextManifestSummary{Present: true, State: state, Budget: review.DefaultContextBudget()}
		lines := contextText(contextWalkthrough(manifest))
		if len(lines) != 1 || !strings.Contains(lines[0], fragment) || !strings.HasSuffix(lines[0], "budget 128 KiB in 32 sources (default)") {
			t.Fatalf("%s: lines = %q", state, lines)
		}
	}
}

const twoFunctionBase = "package p\n\nfunc Avg(xs []int) int {\n\treturn 0\n}\n\nfunc Max(xs []int) int {\n\treturn 0\n}\n"
const twoFunctionHead = "package p\n\nfunc Avg(xs []int) int {\n\treturn 1\n}\n\nfunc Max(xs []int) int {\n\treturn 1\n}\n"

// A function is tested when the manifest places a changed definition in it
// that has a test among its dependents; the list is incomplete whenever the
// index could not say.
func TestMissingVerificationReadsTheContextManifest(t *testing.T) {
	profile := goProfile(t, "p.go", twoFunctionBase, twoFunctionHead)
	both := []review.ContextManifestSummaryDefinition{{Path: "p.go", Line: 3, Dependents: 1, Tests: 1}, {Path: "p.go", Line: 7}}
	for name, test := range map[string]struct {
		manifest   review.ContextManifestSummary
		wantNames  []string
		incomplete bool
	}{
		"one function tested":        {review.ContextManifestSummary{Present: true, State: review.ContextIndexUsed, Complete: true, Changed: both}, []string{"Max"}, false},
		"neither tested":             {review.ContextManifestSummary{Present: true, State: review.ContextIndexUsed, Complete: true, Changed: []review.ContextManifestSummaryDefinition{{Path: "p.go", Line: 3}, {Path: "p.go", Line: 7}}}, []string{"Avg", "Max"}, false},
		"incomplete index":           {review.ContextManifestSummary{Present: true, State: review.ContextIndexUsed, Complete: false, Changed: both}, []string{"Max"}, true},
		"a definition not listed":    {review.ContextManifestSummary{Present: true, State: review.ContextIndexUsed, Complete: true, ChangedNotListed: 1, Changed: both}, []string{"Max"}, true},
		"a function not placed":      {review.ContextManifestSummary{Present: true, State: review.ContextIndexUsed, Complete: true, Changed: both[:1]}, nil, true},
		"no index":                   {review.ContextManifestSummary{Present: true, State: review.ContextIndexUnavailable}, nil, true},
		"a context without manifest": {review.ContextManifestSummary{}, nil, true},
	} {
		notes, notListed, incomplete := missingVerification(profile, test.manifest)
		names := []string{}
		for _, note := range notes {
			names = append(names, note.Name)
		}
		if !reflect.DeepEqual(names, test.wantNames) && !(len(names) == 0 && len(test.wantNames) == 0) || notListed != 0 || incomplete != test.incomplete {
			t.Fatalf("%s: names=%v notListed=%d incomplete=%t", name, names, notListed, incomplete)
		}
	}
}
