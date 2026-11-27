package localreview

import (
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

const (
	avgBase = "package stats\n\n// Avg returns the mean.\nfunc Avg(xs []int) int {\n\tif len(xs) == 0 {\n\t\treturn 0\n\t}\n\tsum := 0\n\tfor _, x := range xs {\n\t\tsum += x\n\t}\n\treturn sum / len(xs)\n}\n\nfunc Max(xs []int) int {\n\tm := xs[0]\n\treturn m\n}\n"
	// The head removes Avg's guard. Avg is head lines 4 to 10; Max is lines
	// 12 to 15 and unchanged.
	avgHead = "package stats\n\n// Avg returns the mean.\nfunc Avg(xs []int) int {\n\tsum := 0\n\tfor _, x := range xs {\n\t\tsum += x\n\t}\n\treturn sum / len(xs)\n}\n\nfunc Max(xs []int) int {\n\tm := xs[0]\n\treturn m\n}\n"
)

// avgDeclarations is the semantic-impact profile of the Avg change: the
// changed declarations of stats.go.
func avgDeclarations(t *testing.T) []semanticimpact.Declaration {
	t.Helper()
	file := func(content string) semanticimpact.File {
		value, err := semanticimpact.NewFile("stats.go", []byte(content))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	changed, err := semanticimpact.NewChangedPath("stats.go")
	if err != nil {
		t.Fatal(err)
	}
	input, err := semanticimpact.NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []semanticimpact.ChangedPath{changed}, []semanticimpact.File{file(avgBase)}, []semanticimpact.File{file(avgHead)})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := semanticimpact.AnalyzeGo(input)
	if err != nil {
		t.Fatal(err)
	}
	return profile.Declarations()
}

// anchored places a finding with the profile, as judgeResult does.
func anchored(t *testing.T, finding ReportFinding) ReportFinding {
	t.Helper()
	finding.Anchor = declarationAnchor(finding, avgDeclarations(t))
	return finding
}

const (
	divideTitle = "Avg may divide by zero"
	divideClaim = "Avg returns sum / len(xs) without checking that xs is non-empty, so an empty slice divides by zero."
	panicTitle  = "Avg panics on empty slice"
	panicClaim  = "The empty-slice guard was removed, and calling Avg(nil) now panics at runtime."
	// The paraphrase shares most of the divide-by-zero statement's words, but
	// fewer than the four fifths of the strict rule.
	paraphraseTitle = "Avg panics on an empty slice"
	paraphraseClaim = "Avg divides sum by len(xs), which is zero when xs is empty, so the division panics."
)

// The changed declaration of the profile anchors a finding that lies inside
// it; a finding that crosses its end, or on unchanged Max, has no anchor.
func TestDeclarationAnchorUsesTheChangedDeclaration(t *testing.T) {
	inside := anchored(t, mergeFixture("a", divideTitle, divideClaim, diagnostics.SeverityError, "stats.go", 9, 9, "correctness"))
	if inside.Anchor != (FindingAnchor{StartLine: 4, EndLine: 10}) {
		t.Fatalf("Avg anchor = %+v, want lines 4-10", inside.Anchor)
	}
	for name, finding := range map[string]ReportFinding{
		"crosses the end":   mergeFixture("b", divideTitle, divideClaim, diagnostics.SeverityError, "stats.go", 9, 12, "correctness"),
		"unchanged Max":     mergeFixture("c", divideTitle, divideClaim, diagnostics.SeverityError, "stats.go", 13, 13, "correctness"),
		"another file":      mergeFixture("d", divideTitle, divideClaim, diagnostics.SeverityError, "other.go", 9, 9, "correctness"),
		"removed base side": {Identity: "e", Path: "stats.go", Side: diagnostics.LineSideBase, StartLine: 5, EndLine: 7},
	} {
		if anchor := anchored(t, finding).Anchor; anchor.set() {
			t.Fatalf("%s: anchored to %+v", name, anchor)
		}
	}
}

// Two specialists' paraphrases of one bug, inside the same changed
// declaration, in one category family and sharing most of their wording, are
// one defect: the strongest is the representative and the other wording is
// kept as "also reported as".
func TestDeduplicateFindingsMergesParaphrasesInOneDeclaration(t *testing.T) {
	// The paraphrase spans the whole function, wider than five lines, so only
	// the declaration anchor makes them one defect.
	divide := anchored(t, mergeFixture("a", divideTitle, divideClaim, diagnostics.SeverityError, "stats.go", 9, 9, "correctness", "hunk", "caller"))
	panics := anchored(t, mergeFixture("b", paraphraseTitle, paraphraseClaim, diagnostics.SeverityError, "stats.go", 4, 10, "reliability"))
	if nearIdentical(defectStatementTokens(divideTitle, divideClaim), defectStatementTokens(paraphraseTitle, paraphraseClaim)) {
		t.Fatal("the paraphrase is near-identical, so it does not exercise the location pass")
	}
	merged := RankFindings(DeduplicateFindings([]FindingOrigin{{Label: "bug_hunter", Findings: []ReportFinding{divide}}, {Label: "backend", Findings: []ReportFinding{panics}}}))
	if len(merged) != 1 || merged[0].Origins != 2 || len(merged[0].Contributors) != 2 {
		t.Fatalf("the Avg paraphrases were not merged: %d groups", len(merged))
	}
	group := merged[0]
	if group.Finding.Identity != "a" || group.Contributors[1].Identity != "b" || group.Contributors[1].MergedBy != MergeRuleSameDeclaration || group.Contributors[0].MergedBy != "" {
		t.Fatalf("representative or rule: %+v", group.Contributors)
	}
	also := group.AlsoReportedAs()
	if len(also) != 1 || also[0].Title != paraphraseTitle || also[0].Claim != paraphraseClaim || also[0].Origin != "backend" {
		t.Fatalf("also reported as = %+v", also)
	}
	text := FindingText(group, group.OriginLabels())
	if !strings.Contains(text, "also reported as: "+paraphraseTitle+" (backend)\n") {
		t.Fatalf("text lacks the other wording:\n%s", text)
	}
	if markdown := findingMarkdown(group, group.OriginLabels()); !strings.Contains(markdown, "   Also reported as: Avg panics on an empty slice (`backend`)\n") {
		t.Fatalf("Markdown lacks the other wording:\n%s", markdown)
	}
	// A single review names no reviewer: it counts the merge and lists the
	// other wording.
	if single := FindingText(group, nil); !strings.Contains(single, "merged duplicates: 1\nalso reported as: "+paraphraseTitle+"\n") {
		t.Fatalf("single-review text lacks the other wording:\n%s", single)
	}
	if markdown := findingMarkdown(group, nil); !strings.Contains(markdown, "   Merged duplicates: 1\n   Also reported as: Avg panics on an empty slice\n") {
		t.Fatalf("single-review Markdown lacks the other wording:\n%s", markdown)
	}
	// A rewording that shares too few words stays a finding of its own: the
	// command cannot tell it from a second defect at the same place.
	unrelated := anchored(t, mergeFixture("c", panicTitle, panicClaim, diagnostics.SeverityError, "stats.go", 4, 10, "reliability"))
	if apart := DeduplicateFindings([]FindingOrigin{{Label: "bug_hunter", Findings: []ReportFinding{divide}}, {Label: "backend", Findings: []ReportFinding{unrelated}}}); len(apart) != 2 || apart[0].Origins != 1 || apart[1].Origins != 1 {
		t.Fatalf("a loosely worded finding at the same place merged: %d groups", len(apart))
	}
	// Without a profile, the same paraphrases within five lines merge by the
	// narrow-range rule.
	divide.Anchor, panics.Anchor = FindingAnchor{}, FindingAnchor{}
	panics.StartLine, panics.EndLine = 7, 9
	near := DeduplicateFindings([]FindingOrigin{{Label: "bug_hunter", Findings: []ReportFinding{divide}}, {Label: "backend", Findings: []ReportFinding{panics}}})
	if len(near) != 1 || near[0].Contributors[1].MergedBy != MergeRuleSameLines {
		t.Fatalf("paraphrases within five lines: %d groups %+v", len(near), near)
	}
	// Wider than five lines and without an anchor, they stay apart.
	panics.StartLine = 4
	if wide := DeduplicateFindings([]FindingOrigin{{Label: "bug_hunter", Findings: []ReportFinding{divide}}, {Label: "backend", Findings: []ReportFinding{panics}}}); len(wide) != 2 {
		t.Fatalf("unanchored paraphrases over six lines merged into %d groups", len(wide))
	}
}

// Two reviewers describe one defect in their own detail: one names the
// expression, the other the failing test and the removed guard. Their
// statements share under half of their words and differ in symbols, so the
// same two findings from one reviewer stay apart, and from two they merge.
func TestDeduplicateFindingsMergesOtherReviewersDetailAtOnePlace(t *testing.T) {
	const title, claim = "Avg divides by zero for an empty slice", "TestAvgEmpty fails: the guard on line 5 was removed, so Avg(nil) divides by zero."
	divide := anchored(t, mergeFixture("a", divideTitle, divideClaim, diagnostics.SeverityError, "stats.go", 9, 9, "correctness", "hunk"))
	detail := anchored(t, mergeFixture("b", title, claim, diagnostics.SeverityWarning, "stats.go", 4, 10, "reliability"))
	one, other := defectStatementTokens(divideTitle, divideClaim), defectStatementTokens(title, claim)
	if relatedStatements(one, other) || !overlappingStatements(one, other) {
		t.Fatal("the statements do not exercise the rule for other origins")
	}
	merged := DeduplicateFindings([]FindingOrigin{{Label: "bug_hunter", Findings: []ReportFinding{divide}}, {Label: "backend", Findings: []ReportFinding{detail}}})
	if len(merged) != 1 || merged[0].Origins != 2 || merged[0].Finding.Identity != "a" || merged[0].Contributors[1].MergedBy != MergeRuleSameDeclaration {
		t.Fatalf("two reviewers' statements of one defect: %+v", merged)
	}
	if also := merged[0].AlsoReportedAs(); len(also) != 1 || also[0].Title != title {
		t.Fatalf("also reported as = %+v", also)
	}
	if apart := DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: []ReportFinding{divide, detail}}}); len(apart) != 2 {
		t.Fatalf("one reviewer's two findings merged into %d groups", len(apart))
	}
}

// Two genuinely distinct bugs on the same line stay apart when their
// categories are of different families, and so do findings in different
// declarations, an anchored and an unanchored finding, and uncategorized
// findings.
func TestDeduplicateFindingsKeepsDistinctBugsOnOneLineApart(t *testing.T) {
	divide := anchored(t, mergeFixture("a", divideTitle, divideClaim, diagnostics.SeverityError, "stats.go", 9, 9, "correctness"))
	cases := map[string]ReportFinding{
		"other family":  anchored(t, mergeFixture("b", "Avg truncates the mean", "Integer division drops the fraction, so the documented mean is rounded down.", diagnostics.SeverityWarning, "stats.go", 9, 9, "documentation")),
		"unanchored":    anchored(t, mergeFixture("b", paraphraseTitle, paraphraseClaim, diagnostics.SeverityError, "stats.go", 9, 12, "correctness")),
		"uncategorized": anchored(t, mergeFixture("b", paraphraseTitle, paraphraseClaim, diagnostics.SeverityError, "stats.go", 9, 9, "")),
		"other anchor": func() ReportFinding {
			f := mergeFixture("b", paraphraseTitle, paraphraseClaim, diagnostics.SeverityError, "stats.go", 9, 9, "correctness")
			f.Anchor = FindingAnchor{StartLine: 8, EndLine: 11}
			return f
		}(),
		"other side":      {Identity: "b", Title: paraphraseTitle, Claim: paraphraseClaim, Severity: diagnostics.SeverityError, Path: "stats.go", Side: diagnostics.LineSideBase, StartLine: 9, EndLine: 9, Category: "correctness", EvidenceIDs: []string{"removed"}},
		"no line overlap": anchored(t, mergeFixture("b", paraphraseTitle, paraphraseClaim, diagnostics.SeverityError, "stats.go", 5, 7, "correctness")),
	}
	for name, other := range cases {
		if merged := DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: []ReportFinding{divide}}, {Label: "bug_hunter", Findings: []ReportFinding{other}}}); len(merged) != 2 {
			t.Fatalf("%s: distinct findings merged into %d groups", name, len(merged))
		}
	}
}

// Two different defects on one line in one changed declaration and one
// category family are two findings: the location alone is no evidence that
// they are the same defect. Neither is shown as the other's wording, and each
// keeps its own corroboration count.
func TestDeduplicateFindingsKeepsDistinctClaimsAtOnePlaceApart(t *testing.T) {
	divide := anchored(t, mergeFixture("a", divideTitle, divideClaim, diagnostics.SeverityError, "stats.go", 9, 9, "correctness"))
	truncate := anchored(t, mergeFixture("b", "Avg truncates the mean", "Integer division drops the fraction, so the mean of 1 and 2 is reported as 1.", diagnostics.SeverityWarning, "stats.go", 9, 9, "correctness"))
	for name, groups := range map[string][]MergedFinding{
		"anchored":   DeduplicateFindings([]FindingOrigin{{Label: "bug_hunter", Findings: []ReportFinding{divide}}, {Label: "backend", Findings: []ReportFinding{truncate}}}),
		"one origin": DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: []ReportFinding{divide, truncate}}}),
		"unanchored": func() []MergedFinding {
			divide, truncate := divide, truncate
			divide.Anchor, truncate.Anchor = FindingAnchor{}, FindingAnchor{}
			return DeduplicateFindings([]FindingOrigin{{Label: "bug_hunter", Findings: []ReportFinding{divide}}, {Label: "backend", Findings: []ReportFinding{truncate}}})
		}(),
	} {
		if len(groups) != 2 {
			t.Fatalf("%s: a division by zero and a truncation merged into %d groups", name, len(groups))
		}
		for _, group := range groups {
			if group.Origins != 1 || len(group.Contributors) != 1 || len(group.AlsoReportedAs()) != 0 {
				t.Fatalf("%s: group %s has %d origins and %d contributors", name, group.Finding.Identity, group.Origins, len(group.Contributors))
			}
		}
	}
}

// Security findings merge only by the strict near-identical rule: two
// security paraphrases in one declaration stay two findings.
func TestDeduplicateFindingsMergesSecurityOnlyByTheStrictRule(t *testing.T) {
	first := anchored(t, mergeFixture("a", "Avg leaks the slice length", "The error message includes len(xs), which reveals the request size to callers.", diagnostics.SeverityWarning, "stats.go", 9, 9, "security"))
	paraphrase := anchored(t, mergeFixture("b", "Request size disclosed through Avg", "Callers learn how many values were sent because Avg reports the count.", diagnostics.SeverityWarning, "stats.go", 9, 9, "security"))
	if merged := DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: []ReportFinding{first}}, {Label: "security_probe", Findings: []ReportFinding{paraphrase}}}); len(merged) != 2 {
		t.Fatalf("security paraphrases merged into %d groups", len(merged))
	}
	repeat := first
	repeat.Identity = "c"
	if merged := DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: []ReportFinding{first}}, {Label: "security_probe", Findings: []ReportFinding{repeat}}}); len(merged) != 1 || merged[0].Contributors[1].MergedBy != MergeRuleNearIdentical {
		t.Fatalf("near-identical security findings: %+v", merged)
	}
	correctness := anchored(t, mergeFixture("d", divideTitle, divideClaim, diagnostics.SeverityError, "stats.go", 9, 9, "correctness"))
	if merged := DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: []ReportFinding{first, correctness}}}); len(merged) != 2 {
		t.Fatalf("a security and a correctness finding merged into %d groups", len(merged))
	}
}

// The two-pass merge is deterministic: the input order of an origin's
// findings does not change the groups, their representatives, contributor
// order or rules.
func TestDeduplicateFindingsLocationRuleIsDeterministic(t *testing.T) {
	divide := anchored(t, mergeFixture("a", divideTitle, divideClaim, diagnostics.SeverityError, "stats.go", 9, 9, "correctness", "hunk", "caller"))
	panics := anchored(t, mergeFixture("b", paraphraseTitle, paraphraseClaim, diagnostics.SeverityError, "stats.go", 4, 10, "reliability"))
	repeat := anchored(t, mergeFixture("c", divideTitle, divideClaim, diagnostics.SeverityWarning, "stats.go", 9, 9, "correctness"))
	style := anchored(t, mergeFixture("d", "Avg lacks a doc example", "The comment of Avg shows no example call.", diagnostics.SeverityInformation, "stats.go", 3, 4, "documentation"))
	one := RankFindings(DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: []ReportFinding{divide, style}}, {Label: "bug_hunter", Findings: []ReportFinding{panics, repeat}}}))
	two := RankFindings(DeduplicateFindings([]FindingOrigin{{Label: "general", Findings: []ReportFinding{style, divide}}, {Label: "bug_hunter", Findings: []ReportFinding{repeat, panics}}}))
	if !reflect.DeepEqual(one, two) {
		t.Fatalf("merge depends on input order:\n%+v\n%+v", one, two)
	}
	if len(one) != 2 || len(one[0].Contributors) != 3 || one[0].Finding.Identity != "a" {
		t.Fatalf("groups: %+v", one)
	}
	rules := []string{}
	for _, contributor := range one[0].Contributors {
		rules = append(rules, contributor.Origin+":"+contributor.Identity+":"+contributor.MergedBy)
	}
	if want := []string{"general:a:", "bug_hunter:b:" + MergeRuleSameDeclaration, "bug_hunter:c:" + MergeRuleNearIdentical}; !reflect.DeepEqual(rules, want) {
		t.Fatalf("contributors = %v, want %v", rules, want)
	}
	// rankEntries, as recorded in a result, is stable too.
	if !reflect.DeepEqual(rankEntries([]ReportFinding{divide, style, panics}, "general", ""), rankEntries([]ReportFinding{panics, divide, style}, "general", "")) {
		t.Fatal("recorded rank entries depend on finding order")
	}
}

// A result recorded under the location-only rule merged findings at one
// place whatever their wording; the reader can still re-derive that rank
// (validRecordedJudgement), while the current rule keeps them apart.
func TestRankEntriesReDeriveTheLocationOnlyRule(t *testing.T) {
	divide := anchored(t, mergeFixture("a", divideTitle, divideClaim, diagnostics.SeverityError, "stats.go", 9, 9, "correctness"))
	truncate := anchored(t, mergeFixture("b", "Avg truncates the mean", "Integer division drops the fraction.", diagnostics.SeverityWarning, "stats.go", 9, 9, "correctness"))
	findings := []ReportFinding{divide, truncate}
	if current := rankEntriesBy(findings, "general", "", false); len(current) != 2 || !reflect.DeepEqual(current, rankEntries(findings, "general", "")) {
		t.Fatalf("current rule: %+v", current)
	}
	legacy := rankEntriesBy(findings, "general", "", true)
	if len(legacy) != 1 || legacy[0].FindingIdentity != "a" || !reflect.DeepEqual(legacy[0].Merged, []string{"b"}) {
		t.Fatalf("location-only rule: %+v", legacy)
	}
}
