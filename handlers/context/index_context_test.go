package context

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

var updateIndexGolden = flag.Bool("update-index-golden", false, "rewrite the index context golden files")

// configureTestHandler, when set, adjusts the handler the text fallback
// helper assembles with.
var configureTestHandler func(*Handler)

type fakeIndexSource struct {
	plan review.ContextPlan
	err  error
}

func (fakeIndexSource) Identity() string { return strings.Repeat("8", 64) }

func (s fakeIndexSource) ContextPlan(context.Context, evidence.RepositoryIdentity, evidence.RevisionIdentity, evidence.RevisionIdentity) (review.ContextPlan, error) {
	return s.plan, s.err
}

const (
	indexCalcBase   = "package calc\n\nfunc Div(a, b int) int {\n\tq := a / b\n\treturn q\n}\n\nfunc Mod(a, b int) int { return a % b }\n"
	indexCalcHead   = "package calc\n\nfunc Div(a, b int) int {\n\tq := a / (b + 0)\n\treturn q\n}\n\nfunc Mod(a, b int) int { return a % b }\n"
	indexCaller     = "package calc\n\n// Half halves.\nfunc Half(a int) int {\n\treturn Div(a, 2)\n}\n"
	indexCallerTest = "package calc\n\nimport \"testing\"\n\nfunc TestDiv(t *testing.T) {\n\tif Div(4, 2) != 2 {\n\t\tt.Fatal(\"div\")\n\t}\n}\n"
	indexScript     = "def scale(x):\n    return x * 2\n"
)

func indexFiles() (map[string][]byte, map[string][]byte) {
	base := map[string][]byte{"calc/div.go": []byte(indexCalcBase), "calc/half.go": []byte(indexCaller), "calc/div_test.go": []byte(indexCallerTest), "tools/scale.py": []byte(indexScript)}
	head := map[string][]byte{"calc/div.go": []byte(indexCalcHead), "calc/half.go": []byte(indexCaller), "calc/div_test.go": []byte(indexCallerTest), "tools/scale.py": []byte(indexScript)}
	return base, head
}

func indexPlan() review.ContextPlan {
	return review.ContextPlan{
		State: review.ContextIndexUsed, Complete: true, Dependents: 2,
		Coverage: review.ContextIndexCoverage{Files: 4, Indexed: 4},
		Items: []review.ContextPlanItem{
			{Stage: review.ContextStageEnclosingSymbol, Path: "calc/div.go", StartLine: 3, EndLine: 6, Rank: 1},
			{Stage: review.ContextStageDirectReference, Path: "calc/half.go", StartLine: 4, EndLine: 6, Rank: 1, Depth: 1},
			{Stage: review.ContextStageRelatedTest, Path: "calc/div_test.go", StartLine: 5, EndLine: 9, Rank: 1, Depth: 1},
			{Stage: review.ContextStageRepositoryMap, Path: "calc/div.go", StartLine: 8, EndLine: 8, Rank: 1},
			{Stage: review.ContextStageRepositoryMap, Path: "tools/scale.py", StartLine: 1, EndLine: 1, Rank: 2},
		},
		StageOmitted: map[review.ContextStage]int{review.ContextStageDirectReference: 3},
		Changed:      []review.ContextPlanDefinition{{Path: "calc/div.go", StartLine: 3, EndLine: 6, Dependents: 2, Tests: 1}},
		Checks:       []string{"unit_tests", "lint"},
	}
}

func assembleWithIndex(t *testing.T, source IndexContextSource, budget review.ContextBudget) textFallbackResult {
	t.Helper()
	configureTestHandler = func(h *Handler) { h.index, h.budget = source, budget }
	defer func() { configureTestHandler = nil }()
	base, head := indexFiles()
	return assembleTextFallback(t, base, head)
}

// renderIndexContext lists a packet's sources and its manifest, without
// digests, for the golden files.
func renderIndexContext(t *testing.T, result textFallbackResult) string {
	t.Helper()
	if result.failure != 0 {
		t.Fatalf("assembly failed: %s", result.failure)
	}
	packet := result.assembly.Packet
	payload := result.request.Payload()
	if err := review.ValidateContextPacketRequest(payload, packet.Identity(), packet.ReviewScopeIdentity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), result.assembly.Snapshot, packet.EvidenceItems()); err != nil {
		t.Fatalf("assembled context rejected: %v", err)
	}
	summary, err := review.ContextManifestOf(payload)
	if err != nil || !summary.Present {
		t.Fatalf("manifest = %+v, %v", summary, err)
	}
	var b strings.Builder
	for _, source := range packet.Sources() {
		r := source.EvidenceItem().SourceRange()
		fmt.Fprintf(&b, "source %s %s:%d-%d\n", source.Stage(), r.Path(), r.StartLine(), r.EndLine())
	}
	fmt.Fprintf(&b, "budget %s %d bytes %d sources\n", summary.Budget.Basis, summary.Budget.MaxSourceBytes, summary.Budget.MaxSources)
	fmt.Fprintf(&b, "index %s complete %t dependents %d\n", summary.State, summary.Complete, summary.Dependents)
	for _, source := range summary.Included {
		fmt.Fprintf(&b, "included %s rank %d depth %d %s:%d-%d\n", source.Stage, source.Rank, source.Depth, source.Path, source.StartLine, source.EndLine)
	}
	for _, omitted := range summary.Omitted {
		fmt.Fprintf(&b, "omitted %s %s %d\n", omitted.Stage, omitted.Reason, omitted.Count)
	}
	for _, changed := range summary.Changed {
		fmt.Fprintf(&b, "changed %s:%d dependents %d tests %d\n", changed.Path, changed.Line, changed.Dependents, changed.Tests)
	}
	fmt.Fprintf(&b, "changed not listed %d\nchecks %v\n", summary.ChangedNotListed, summary.Checks)
	return b.String()
}

func checkIndexGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "index_"+name+".golden")
	if *updateIndexGolden {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatalf("%s differs from its golden file:\n%s", name, got)
	}
}

func TestIndexContextFollowsThePlanInPriorityOrder(t *testing.T) {
	result := assembleWithIndex(t, fakeIndexSource{plan: indexPlan()}, review.RouteContextBudget(200_000, 8_000))
	checkIndexGolden(t, "full", renderIndexContext(t, result))
	again := assembleWithIndex(t, fakeIndexSource{plan: indexPlan()}, review.RouteContextBudget(200_000, 8_000))
	if !bytes.Equal(result.request.Payload(), again.request.Payload()) {
		t.Fatal("equal plans gave different packets")
	}
	base, head := indexFiles()
	plain := assembleTextFallback(t, base, head)
	instructions, err := review.TrustedModelRequestInstructions(result.request.Payload())
	without, plainErr := review.TrustedModelRequestInstructions(plain.request.Payload())
	if err != nil || plainErr != nil || instructions != without {
		t.Fatal("index context changed the trusted system channel")
	}
	ranges, err := review.ContextIndexSourceRanges(result.request.Payload())
	if err != nil || len(ranges) != 5 {
		t.Fatalf("index source ranges = %v, %v", ranges, err)
	}
}

func TestIndexContextCutsByBytesAndSources(t *testing.T) {
	// The changed hunk and the stated budget leave room for the enclosing
	// definition only; later items are left out with their reasons.
	budget := review.ContextBudget{Basis: review.ContextBudgetRouteWindow, RouteContextTokens: 1, MaxSourceBytes: uint32(len("\tq := a / (b + 0)\n") + len("func Div(a, b int) int {\n\tq := a / (b + 0)\n\treturn q\n}\n") + 20), MaxSources: 32}
	checkIndexGolden(t, "bytes", renderIndexContext(t, assembleWithIndex(t, fakeIndexSource{plan: indexPlan()}, budget)))
	budget = review.ContextBudget{Basis: review.ContextBudgetRouteWindow, RouteContextTokens: 1, MaxSourceBytes: 64 << 10, MaxSources: 3}
	checkIndexGolden(t, "sources", renderIndexContext(t, assembleWithIndex(t, fakeIndexSource{plan: indexPlan()}, budget)))
}

func TestIndexContextLeavesOutBadAndDuplicateRanges(t *testing.T) {
	plan := indexPlan()
	plan.Items = []review.ContextPlanItem{
		{Stage: review.ContextStageEnclosingSymbol, Path: "calc/div.go", StartLine: 4, EndLine: 4, Rank: 1},
		{Stage: review.ContextStageDirectReference, Path: "missing.go", StartLine: 1, EndLine: 2, Rank: 1, Depth: 1},
		{Stage: review.ContextStageDirectReference, Path: "calc/half.go", StartLine: 40, EndLine: 41, Rank: 2, Depth: 1},
		{Stage: review.ContextStageRepositoryMap, Path: "calc/half.go", StartLine: 4, EndLine: 90, Rank: 1},
	}
	checkIndexGolden(t, "rejected", renderIndexContext(t, assembleWithIndex(t, fakeIndexSource{plan: plan}, review.DefaultContextBudget())))
}

func TestReviewProceedsWithoutAnIndex(t *testing.T) {
	cases := map[string]struct {
		source IndexContextSource
		state  string
	}{
		"none":        {nil, review.ContextIndexUnavailable},
		"failed":      {fakeIndexSource{err: errors.New("damaged")}, review.ContextIndexFailed},
		"over_budget": {fakeIndexSource{plan: review.UnavailableContextPlan(review.ContextIndexOverBudget)}, review.ContextIndexOverBudget},
		"unknown":     {fakeIndexSource{plan: review.ContextPlan{State: "partial"}}, review.ContextIndexFailed},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			result := assembleWithIndex(t, c.source, review.DefaultContextBudget())
			if result.failure != 0 {
				t.Fatalf("assembly failed: %s", result.failure)
			}
			summary, err := review.ContextManifestOf(result.request.Payload())
			if err != nil || summary.State != c.state || summary.Complete || len(summary.Included) != 0 || summary.Budget.Basis != review.ContextBudgetDefault {
				t.Fatalf("manifest = %+v, %v", summary, err)
			}
			for _, source := range result.assembly.Packet.Sources() {
				if indexStage(source.Stage()) {
					t.Fatalf("index context without an index: %s", source.Stage())
				}
			}
		})
	}
}

func TestRouteContextBudget(t *testing.T) {
	cases := []struct {
		window, output uint32
		bytes          uint32
		sources        uint8
		basis          string
	}{
		{0, 4096, 128 << 10, 32, review.ContextBudgetDefault},
		{32768, 4096, 14336, 32, review.ContextBudgetRouteWindow},
		{4096, 8192, 8 << 10, 32, review.ContextBudgetRouteWindow},
		{400_000, 16_000, 192_000, 64, review.ContextBudgetRouteWindow},
		{10_000_000, 16_000, 1 << 20, 64, review.ContextBudgetRouteWindow},
	}
	for _, c := range cases {
		got := review.RouteContextBudget(c.window, c.output)
		if got.MaxSourceBytes != c.bytes || got.MaxSources != c.sources || got.Basis != c.basis {
			t.Errorf("RouteContextBudget(%d, %d) = %+v", c.window, c.output, got)
		}
	}
}
