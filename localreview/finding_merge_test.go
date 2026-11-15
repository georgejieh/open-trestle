package localreview

import (
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
)

func mergeFixture(identity, title, claim string, severity diagnostics.Severity, path string, start, end uint32, category string, evidence ...string) ReportFinding {
	if len(evidence) == 0 {
		evidence = []string{"evidence-" + identity}
	}
	return ReportFinding{Identity: identity, Title: title, Claim: claim, Severity: severity, Path: path, StartLine: start, EndLine: end, Category: category, EvidenceIDs: evidence}
}

const (
	zeroGuardTitle = "Division by zero when the divisor is zero"
	zeroGuardClaim = "Divide returns a / b without checking that b is not zero, so a zero divisor panics."
)

// The same defect reported twice, word for word, at the same lines merges
// into one finding that names both contributors.
func TestDeduplicateFindingsMergesExactDuplicates(t *testing.T) {
	first := mergeFixture("a", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 4, 6, "correctness")
	second := mergeFixture("b", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 4, 6, "correctness")
	merged := DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: []ReportFinding{first}}, {Label: "bug_hunter", Findings: []ReportFinding{second}}})
	if len(merged) != 1 || len(merged[0].Contributors) != 2 || merged[0].Origins != 2 || MergedDuplicates(merged) != 1 {
		t.Fatalf("exact duplicates were not merged: %+v", merged)
	}
	if merged[0].Contributors[0].Origin != "general" || merged[0].Contributors[1].Origin != "bug_hunter" {
		t.Fatalf("contributors are not in origin order: %+v", merged[0].Contributors)
	}
}

// Overlapping (not equal) ranges with near-identical statements merge; the
// representative is the finding with the stronger verified evidence, and its
// own location is reported.
func TestDeduplicateFindingsMergesOverlappingNearIdenticalStatements(t *testing.T) {
	weak := mergeFixture("a", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 2, 8, "correctness")
	// Punctuation, case and a plural differ; the normalized statement is the same.
	strong := mergeFixture("b", "Division by zero when the divisor is zero!", "DIVIDE returns a / b without checking that b is not zero; so zero divisors panic.", diagnostics.SeverityError, "calc.go", 5, 6, "correctness", "hunk-1", "hunk-2")
	merged := DeduplicateFindings([]FindingOrigin{{Label: "run-1", Findings: []ReportFinding{weak}}, {Label: "run-2", Findings: []ReportFinding{strong}}})
	if len(merged) != 1 {
		t.Fatalf("overlapping near-identical findings were not merged: %d groups", len(merged))
	}
	if merged[0].Finding.Identity != "b" || merged[0].Finding.StartLine != 5 || merged[0].Finding.EndLine != 6 {
		t.Fatalf("representative is not the strongest verified finding: %+v", merged[0].Finding)
	}
	if got := merged[0].MergedIdentities(); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("merged identities = %v, want [a]", got)
	}
}

// Categories in one family (behaviour, or code health) are compatible; an
// uncategorized finding is compatible with any category.
func TestDeduplicateFindingsMergesCompatibleCategories(t *testing.T) {
	for _, pair := range [][2]string{{"correctness", "reliability"}, {"performance", "correctness"}, {"style", "maintainability"}, {"", "concurrency"}, {"security", "security"}} {
		first := mergeFixture("a", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityWarning, "calc.go", 4, 6, pair[0])
		second := mergeFixture("b", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityWarning, "calc.go", 4, 6, pair[1])
		if merged := DeduplicateFindings([]FindingOrigin{{Label: "m0", Findings: []ReportFinding{first}}, {Label: "m1", Findings: []ReportFinding{second}}}); len(merged) != 1 {
			t.Fatalf("compatible categories %q and %q did not merge", pair[0], pair[1])
		}
	}
}

// A finding stays separate when any key differs: path, side, line overlap,
// category family, or a statement that is only similar, not near-identical.
func TestDeduplicateFindingsKeepsNonDuplicatesApart(t *testing.T) {
	base := mergeFixture("a", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 4, 6, "correctness")
	cases := map[string]ReportFinding{
		"other path":          mergeFixture("b", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "other.go", 4, 6, "correctness"),
		"no line overlap":     mergeFixture("b", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 7, 9, "correctness"),
		"incompatible family": mergeFixture("b", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 4, 6, "documentation"),
		"security apart":      mergeFixture("b", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 4, 6, "security"),
		"paraphrase":          mergeFixture("b", "Zero divisor crashes Divide", "Calling Divide with b equal to 0 panics at runtime because the guard is missing.", diagnostics.SeverityError, "calc.go", 4, 6, "correctness"),
		"other identifier":    mergeFixture("b", "Division by zero when the divisor is zero", "Divide returns a / c without checking that c is not zero, so a zero divisor panics.", diagnostics.SeverityError, "calc.go", 4, 6, "correctness"),
		"other camelCase":     mergeFixture("b", zeroGuardTitle, "Divide returns a / b without checking that maxDivisor is not zero, so a zero divisor panics.", diagnostics.SeverityError, "calc.go", 4, 6, "correctness"),
	}
	limit := mergeFixture("c", "Retry limit is too low", "The client stops after 10 retries and drops queued writes when the limit is reached.", diagnostics.SeverityWarning, "calc.go", 4, 6, "reliability")
	otherLimit := mergeFixture("d", "Retry limit is too low", "The client stops after 100 retries and drops queued writes when the limit is reached.", diagnostics.SeverityWarning, "calc.go", 4, 6, "reliability")
	if merged := DeduplicateFindings([]FindingOrigin{{Label: "m0", Findings: []ReportFinding{limit}}, {Label: "m1", Findings: []ReportFinding{otherLimit}}}); len(merged) != 2 {
		t.Fatal("statements that differ only in a number merged")
	}
	baseSide := base
	baseSide.Identity, baseSide.Side, baseSide.HeadLine = "b", diagnostics.LineSideBase, 3
	cases["base side"] = baseSide
	for name, other := range cases {
		merged := DeduplicateFindings([]FindingOrigin{{Label: "m0", Findings: []ReportFinding{base}}, {Label: "m1", Findings: []ReportFinding{other}}})
		if len(merged) != 2 || MergedDuplicates(merged) != 0 {
			t.Fatalf("%s: distinct findings merged into %d groups", name, len(merged))
		}
	}
}

// One run may repeat a defect; near-identical findings of one origin merge.
// Two distinct defects of one origin in one hunk stay apart.
func TestDeduplicateFindingsWithinOneOrigin(t *testing.T) {
	first := mergeFixture("a", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 4, 6, "correctness")
	repeat := mergeFixture("b", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityWarning, "calc.go", 5, 5, "correctness")
	distinct := mergeFixture("c", "Overflow when adding large totals", "Sum adds two int32 totals and can overflow for large values.", diagnostics.SeverityWarning, "calc.go", 4, 6, "correctness")
	merged := DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: []ReportFinding{first, repeat, distinct}}})
	if len(merged) != 2 || MergedDuplicates(merged) != 1 {
		t.Fatalf("within one origin: %d groups, %d duplicates", len(merged), MergedDuplicates(merged))
	}
	for _, group := range merged {
		if group.Finding.Identity == "a" && (group.Origins != 1 || len(group.Contributors) != 2) {
			t.Fatalf("a repeated finding of one origin counts as %d origins", group.Origins)
		}
	}
}

// A finding joins a group only through the representative's own range and
// statement, never through a finding the group already absorbed.
func TestDeduplicateFindingsDoesNotChainThroughAbsorbedFindings(t *testing.T) {
	representative := mergeFixture("a", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 10, 20, "correctness", "e1", "e2")
	absorbed := mergeFixture("b", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 18, 30, "correctness")
	// Overlaps only the absorbed finding's range.
	late := mergeFixture("c", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 25, 40, "correctness")
	merged := DeduplicateFindings([]FindingOrigin{{Label: "m0", Findings: []ReportFinding{representative}}, {Label: "m1", Findings: []ReportFinding{absorbed}}, {Label: "m2", Findings: []ReportFinding{late}}})
	if len(merged) != 2 || MergedDuplicates(merged) != 1 {
		t.Fatalf("a finding chained into a group through an absorbed range: %d groups", len(merged))
	}
}

// Ranking orders by final severity, then verification confidence (distinct
// origins that confirmed the defect, then independence), then evidence
// strength (distinct evidence, then a narrower range), then location.
func TestRankFindingsOrder(t *testing.T) {
	low := mergeFixture("low", "Unused variable total", "total is assigned but never read.", diagnostics.SeverityInformation, "a.go", 1, 1, "maintainability")
	medium := mergeFixture("medium", "Unbounded retry loop", "The loop retries forever on error.", diagnostics.SeverityWarning, "a.go", 3, 3, "reliability")
	highOne := mergeFixture("high-one", "Missing authorization check", "The handler mutates the account without an authorization check.", diagnostics.SeverityError, "z.go", 9, 9, "security")
	highCorroborated := mergeFixture("high-two", "Nil map write panics", "The cache map is written before it is initialized.", diagnostics.SeverityError, "y.go", 5, 5, "correctness")
	highCorroboratedAgain := mergeFixture("high-two-again", "Nil map write panics", "The cache map is written before it is initialized.", diagnostics.SeverityError, "y.go", 5, 5, "correctness")
	highMoreEvidence := mergeFixture("high-three", "Token compared with ==", "The secret token is compared with a non-constant-time equality.", diagnostics.SeverityError, "x.go", 2, 2, "security", "e1", "e2")
	merged := DeduplicateFindings([]FindingOrigin{
		{Label: "general", Independence: "distinct_model", Findings: []ReportFinding{low, medium, highOne, highCorroborated, highMoreEvidence}},
		{Label: "bug_hunter", Independence: "distinct_model", Findings: []ReportFinding{highCorroboratedAgain}},
	})
	ranked := RankFindings(merged)
	want := []string{"high-two", "high-three", "high-one", "medium", "low"}
	got := []string{}
	for index, value := range ranked {
		got = append(got, value.Finding.Identity)
		if value.Rank != index+1 {
			t.Fatalf("rank %d at position %d", value.Rank, index)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rank order = %v, want %v", got, want)
	}
}

// Independence breaks a confidence tie between single-origin findings.
func TestRankFindingsPrefersStrongerIndependence(t *testing.T) {
	a := mergeFixture("a", "Missing authorization check", "The handler mutates the account without a check.", diagnostics.SeverityError, "a.go", 1, 1, "security")
	b := mergeFixture("b", "Nil map write panics", "The cache map is written before it is initialized.", diagnostics.SeverityError, "b.go", 1, 1, "correctness")
	ranked := RankFindings(DeduplicateFindings([]FindingOrigin{
		{Label: "run-1", Independence: "distinct_route", Findings: []ReportFinding{a}},
		{Label: "run-2", Independence: "distinct_provider", Findings: []ReportFinding{b}},
	}))
	if ranked[0].Finding.Identity != "b" || ranked[0].Independence != "distinct_provider" {
		t.Fatalf("stronger independence did not rank first: %+v", ranked[0])
	}
}

// By default the text shows confirmed high and medium findings; the rest are
// counted. Duplicates never count as hidden findings.
func TestFindingVisibilityCounts(t *testing.T) {
	findings := []ReportFinding{
		mergeFixture("h", "High one", "A high finding statement.", diagnostics.SeverityError, "a.go", 1, 1, "security"),
		mergeFixture("m", "Medium one", "A medium finding statement.", diagnostics.SeverityWarning, "a.go", 3, 3, "reliability"),
		mergeFixture("l", "Low one", "A low finding statement.", diagnostics.SeverityInformation, "a.go", 5, 5, "style"),
		mergeFixture("l2", "Low one", "A low finding statement.", diagnostics.SeverityInformation, "a.go", 5, 5, "style"),
		mergeFixture("n", "Hint one", "A hint finding statement.", diagnostics.SeverityHint, "a.go", 7, 7, "documentation"),
	}
	ranked := RankFindings(DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: findings}}))
	shown, hidden := 0, 0
	for _, value := range ranked {
		if value.ShownByDefault() {
			shown++
		} else {
			hidden++
		}
	}
	if len(ranked) != 4 || shown != 2 || hidden != 2 {
		t.Fatalf("visibility: groups=%d shown=%d hidden=%d", len(ranked), shown, hidden)
	}
}

// A group is pre-existing only when every contributor is; one contributor on
// a changed line makes the defect part of the change.
func TestMergedFindingPreExistingNeedsEveryContributor(t *testing.T) {
	old := mergeFixture("a", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 4, 6, "correctness")
	old.PreExisting = true
	introduced := mergeFixture("b", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 5, 6, "correctness")
	merged := DeduplicateFindings([]FindingOrigin{{Label: "m0", Findings: []ReportFinding{old}}, {Label: "m1", Findings: []ReportFinding{introduced}}})
	if len(merged) != 1 || merged[0].PreExisting() {
		t.Fatalf("a defect with one introduced contributor was classified pre-existing")
	}
	again := old
	again.Identity = "c"
	if merged := DeduplicateFindings([]FindingOrigin{{Label: "m0", Findings: []ReportFinding{old}}, {Label: "m1", Findings: []ReportFinding{again}}}); !merged[0].PreExisting() {
		t.Fatal("a defect whose every contributor is pre-existing was not classified pre-existing")
	}
}

// Merging is deterministic: the input order of one origin's findings does not
// change the groups or their representatives.
func TestDeduplicateFindingsIsDeterministic(t *testing.T) {
	a := mergeFixture("a", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 4, 6, "correctness")
	b := mergeFixture("b", zeroGuardTitle, zeroGuardClaim, diagnostics.SeverityError, "calc.go", 4, 6, "correctness")
	c := mergeFixture("c", "Overflow when adding large totals", "Sum adds two int32 totals and can overflow.", diagnostics.SeverityWarning, "calc.go", 10, 12, "correctness")
	one := RankFindings(DeduplicateFindings([]FindingOrigin{{Label: "m0", Findings: []ReportFinding{a, b, c}}}))
	two := RankFindings(DeduplicateFindings([]FindingOrigin{{Label: "m0", Findings: []ReportFinding{c, b, a}}}))
	if !reflect.DeepEqual(one, two) {
		t.Fatalf("merge depends on input order:\n%+v\n%+v", one, two)
	}
}
