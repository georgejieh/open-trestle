package patternhygiene

import (
	"reflect"
	"strings"
	"testing"
)

// matchRule reports whether one line of a file matches a rule, using the same
// lexing and file facts as Analyze.
func matchRule(t *testing.T, id, filePath, content string, line int) bool {
	t.Helper()
	rule, ok := RuleByID(id)
	if !ok {
		t.Fatalf("rule %s is not in the table", id)
	}
	language, ok := LanguageOf(filePath)
	if !ok {
		t.Fatalf("%s has no supported language", filePath)
	}
	lines := contextLines(filePath, language, []byte(content))
	return ruleApplies(rule, language) && rule.match(lines[line-1])
}

func TestRulesMatchPositiveAndNegativeFixtures(t *testing.T) {
	cases := []struct {
		rule, path, content string
		line                int
		want                bool
	}{
		// Go: time.Sleep outside tests only, and never inside a string or comment.
		{"go.time_sleep", "pkg/a.go", "package pkg\nfunc f() { time.Sleep(time.Second) }\n", 2, true},
		{"go.time_sleep", "pkg/a_test.go", "package pkg\nfunc f() { time.Sleep(time.Second) }\n", 2, false},
		{"go.time_sleep", "pkg/a.go", "package pkg\nvar s = \"time.Sleep(1)\"\n", 2, false},
		{"go.time_sleep", "pkg/a.go", "package pkg\n// time.Sleep(1) would be wrong\n", 2, false},
		{"go.time_sleep", "pkg/a.go", "package pkg\nvar s = `\ntime.Sleep(1)\n`\n", 3, false},
		// Go: panic in a library package, not in main or tests, not a method.
		{"go.library_panic", "pkg/a.go", "package pkg\nfunc f() { panic(\"x\") }\n", 2, true},
		{"go.library_panic", "cmd/a.go", "package main\nfunc f() { panic(\"x\") }\n", 2, false},
		{"go.library_panic", "pkg/a_test.go", "package pkg\nfunc f() { panic(\"x\") }\n", 2, false},
		{"go.library_panic", "pkg/a.go", "package pkg\nfunc f() { t.panic(1); mypanic(2) }\n", 2, false},
		// Go: fmt print family in a library package only.
		{"go.library_print", "pkg/a.go", "package pkg\nfunc f() { fmt.Println(x) }\n", 2, true},
		{"go.library_print", "pkg/a.go", "package pkg\nfunc f() { fmt.Printf(\"%d\", x) }\n", 2, true},
		{"go.library_print", "pkg/a.go", "package pkg\nfunc f() { fmt.Fprintf(w, \"%d\", x) }\n", 2, false},
		{"go.library_print", "cmd/a.go", "package main\nfunc f() { fmt.Println(x) }\n", 2, false},
		// Go: nolint needs a // reason.
		{"go.nolint_without_reason", "pkg/a.go", "package pkg\nx := f() //nolint:errcheck\n", 2, true},
		{"go.nolint_without_reason", "pkg/a.go", "package pkg\nx := f() //nolint:errcheck // closed by caller\n", 2, false},
		{"go.nolint_without_reason", "pkg/a.go", "package pkg\n// nolint is discussed here\n", 2, false},
		// JavaScript and TypeScript.
		{"js.use_effect", "web/App.tsx", "useEffect(() => {}, [])\n", 1, true},
		{"js.use_effect", "web/App.tsx", "React.useEffect(() => {}, [])\n", 1, true},
		{"js.use_effect", "web/hooks.ts", "useEffect(() => {}, [])\n", 1, false},
		{"js.use_effect", "web/App.tsx", "const s = 'useEffect(x)'\n", 1, false},
		{"js.set_timeout", "web/a.js", "setTimeout(run, 10)\n", 1, true},
		{"js.set_timeout", "web/a.js", "window.setTimeout(run, 10)\n", 1, true},
		{"js.set_timeout", "web/a.test.js", "setTimeout(run, 10)\n", 1, false},
		{"js.set_timeout", "web/a.js", "jest.setTimeout(10)\n", 1, false},
		{"js.set_timeout", "web/a.js", "// setTimeout(run) is avoided\n", 1, false},
		{"js.request_animation_frame", "web/a.ts", "requestAnimationFrame(draw)\n", 1, true},
		{"js.request_animation_frame", "web/a.spec.ts", "requestAnimationFrame(draw)\n", 1, false},
		{"js.eslint_disable", "web/a.js", "// eslint-disable-next-line no-console\n", 1, true},
		{"js.eslint_disable", "web/a.js", "/* eslint-disable */\n", 1, true},
		{"js.eslint_disable", "web/a.js", "// we never eslint-disable here\n", 1, false},
		{"js.ts_ignore", "web/a.ts", "// @ts-ignore\n", 1, true},
		{"js.ts_ignore", "web/a.ts", "// @ts-expect-error: known\n", 1, false},
		// Python.
		{"py.mutable_default", "app/a.py", "def f(x, items=[]):\n", 1, true},
		{"py.mutable_default", "app/a.py", "async def f(opts={}, n=1):\n", 1, true},
		{"py.mutable_default", "app/a.py", "def f(x, items=None):\n", 1, false},
		{"py.mutable_default", "app/a.py", "items = []\n", 1, false},
		{"py.bare_except", "app/a.py", "try:\n    f()\nexcept:\n    pass\n", 3, true},
		{"py.bare_except", "app/a.py", "try:\n    f()\nexcept ValueError:\n    pass\n", 3, false},
		{"py.type_ignore", "app/a.py", "x = f()  # type: ignore\n", 1, true},
		{"py.type_ignore", "app/a.py", "x = '# type: ignore'\n", 1, false},
		{"py.noqa_without_code", "app/a.py", "import os  # noqa\n", 1, true},
		{"py.noqa_without_code", "app/a.py", "import os  # noqa: F401\n", 1, false},
		{"py.noqa_without_code", "app/a.py", "x = 1  # we avoid noqa here\n", 1, false},
		{"py.noqa_without_code", "app/a.py", "s = \"\"\"\nimport os  # noqa\n\"\"\"\n", 2, false},
	}
	for _, c := range cases {
		if got := matchRule(t, c.rule, c.path, c.content, c.line); got != c.want {
			t.Errorf("%s on %s line %d of %q = %v, want %v", c.rule, c.path, c.line, c.content, got, c.want)
		}
	}
}

func TestRulesTableIsCuratedAndDocumented(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range Rules {
		if rule.ID == "" || seen[rule.ID] || rule.Pattern == "" || rule.Why == "" || len(rule.Language) == 0 || rule.match == nil {
			t.Fatalf("rule %+v is incomplete or repeated", rule.ID)
		}
		seen[rule.ID] = true
	}
	if len(Rules) != 13 {
		t.Fatalf("the curated table has %d rules; update the documentation when it changes", len(Rules))
	}
}

func TestCommentDetectorsArePositiveAndConservative(t *testing.T) {
	workarounds := []struct {
		comment string
		want    bool
	}{
		{" workaround for the upstream bug", true},
		{" HACK: retry twice", true},
		{" temporary fix until the API is fixed", true},
		{" temporarily disable the cache", true},
		{" return nil for now", true},
		{" we retry because the server doesn't send a final frame", true},
		{" to avoid a deadlock we copy the slice", true},
		{" create a temporary file", false},
		{" because the slice is sorted, use binary search", false},
		{" hackathon entry point", false},
		{" avoids copying", false},
	}
	for _, c := range workarounds {
		if got := workaroundComment(c.comment); got != c.want {
			t.Errorf("workaroundComment(%q) = %v, want %v", c.comment, got, c.want)
		}
	}
	todos := []struct {
		comment string
		want    bool
	}{
		{" TODO: remove", true},
		{" FIXME(sam) leaks", true},
		{" XXX", true},
		{" TODO(#123): remove", false},
		{" TODO: see JIRA-42", false},
		{" FIXME https://example.com/issues/7", false},
		{" TODO remove after issue 99", false},
		{" format is XXX-XXX-XXXX", false},
		{" these todos are tracked", false},
	}
	for _, c := range todos {
		if got := unreferencedTODO(c.comment); got != c.want {
			t.Errorf("unreferencedTODO(%q) = %v, want %v", c.comment, got, c.want)
		}
	}
	directives := []struct {
		line string
		want bool
	}{
		{"- NEVER call the API directly", true},
		{"- You MUST NOT commit secrets", true},
		{"- **Always** run the tests", true},
		{"- __never__ skip review", true},
		{"- Prefer small commits; never force-push shared branches", false},
		{"- Run tests always before pushing", false},
		{"- MUST be reviewed", false},
	}
	for _, c := range directives {
		if got := absoluteDirective(c.line); got != c.want {
			t.Errorf("absoluteDirective(%q) = %v, want %v", c.line, got, c.want)
		}
	}
	files := map[string]bool{
		"AGENTS.md": true, "docs/CLAUDE.md": true, ".cursor/rules/go.mdc": true, ".github/copilot-instructions.md": true,
		".trestle/review-instructions.md": true, "agentprofile/skills/bug_hunter.md": true, "tools/x/SKILL.md": true,
		"README.md": false, ".cursor/settings.json": false, "docs/skills.go": false, "copilot-instructions.md": false,
	}
	for file, want := range files {
		if got := RuleFile(file); got != want {
			t.Errorf("RuleFile(%q) = %v, want %v", file, got, want)
		}
	}
}

func TestAnalyzeCountsBaseAgainstHeadPerDirectory(t *testing.T) {
	baseSibling := "package pkg\nfunc a() { time.Sleep(1) }\n"
	baseChanged := "package pkg\nfunc b() {}\n"
	headChanged := "package pkg\nfunc b() {\n\ttime.Sleep(2)\n\tpanic(\"no\")\n}\n"
	input := Input{
		Changes: []Change{{Path: "pkg/b.go", Added: []LineRange{{2, 5}}}},
		Base:    []File{{"pkg/a.go", []byte(baseSibling)}, {"pkg/b.go", []byte(baseChanged)}, {"other/c.go", []byte("package other\nfunc c() { time.Sleep(1); time.Sleep(2) }\n")}},
		Head:    []File{{"pkg/a.go", []byte(baseSibling)}, {"pkg/b.go", []byte(headChanged)}},
	}
	report := Analyze(input)
	want := []Increase{
		{Rule: "go.time_sleep", Directory: "pkg", Base: 1, Head: 2, Spreading: true, Added: []Location{{"pkg/b.go", 3}}},
		{Rule: "go.library_panic", Directory: "pkg", Base: 0, Head: 1, Spreading: false, Added: []Location{{"pkg/b.go", 4}}},
	}
	if !reflect.DeepEqual(report.Increases, want) {
		t.Fatalf("increases = %+v, want %+v", report.Increases, want)
	}
	if report.Counts.IncreasedAntiPatterns != 2 || report.Counts.SpreadingAntiPatterns != 1 {
		t.Fatalf("counts = %+v", report.Counts)
	}
}

func TestAnalyzeReportsNoIncreaseWhenCountsDoNotRise(t *testing.T) {
	// The change moves a sleep from one file to another in the same directory:
	// the directory count is unchanged, so nothing spreads.
	input := Input{
		Changes: []Change{{Path: "pkg/a.go", Added: []LineRange{{2, 2}}}, {Path: "pkg/b.go", Added: []LineRange{{2, 2}}}},
		Base:    []File{{"pkg/a.go", []byte("package pkg\nfunc a() { time.Sleep(1) }\n")}, {"pkg/b.go", []byte("package pkg\nfunc b() {}\n")}},
		Head:    []File{{"pkg/a.go", []byte("package pkg\nfunc a() {}\n")}, {"pkg/b.go", []byte("package pkg\nfunc b() { time.Sleep(1) }\n")}},
	}
	if report := Analyze(input); len(report.Increases) != 0 || report.Counts.IncreasedAntiPatterns != 0 {
		t.Fatalf("a moved occurrence was reported as an increase: %+v", report)
	}
}

func TestAnalyzeDoesNotCompareUnreadDirectories(t *testing.T) {
	input := Input{
		Changes: []Change{{Path: "pkg/b.go", Added: []LineRange{{2, 2}}}},
		Base:    []File{{"pkg/b.go", []byte("package pkg\n\n")}},
		Head:    []File{{"pkg/b.go", []byte("package pkg\nfunc b() { time.Sleep(1) }\n")}},
		Unread:  []string{"pkg"},
	}
	report := Analyze(input)
	if len(report.Increases) != 0 || report.UnreadDirectories != 1 {
		t.Fatalf("an unread directory was compared: %+v", report)
	}
}

func TestAnalyzeObservesAddedCommentsAndPairsSuppressions(t *testing.T) {
	head := strings.Join([]string{
		"package pkg",
		"func f() {",
		"\t// workaround: the client closes early",
		"\tx := g() //nolint:errcheck",
		"\t// TODO: remove",
		"\ty := h() //nolint:errcheck // checked below",
		"}",
		"// TODO: old, unchanged",
		"",
	}, "\n")
	input := Input{
		Changes: []Change{{Path: "pkg/a.go", Added: []LineRange{{3, 6}}}},
		Head:    []File{{"pkg/a.go", []byte(head)}},
	}
	report := Analyze(input)
	wantObservations := []Observation{
		{KindWorkaroundComment, "", Location{"pkg/a.go", 3}},
		{KindSuppression, "go.nolint", Location{"pkg/a.go", 4}},
		{KindUnreferencedTODO, "", Location{"pkg/a.go", 5}},
		{KindSuppression, "go.nolint", Location{"pkg/a.go", 6}},
	}
	if !reflect.DeepEqual(report.Observations, wantObservations) {
		t.Fatalf("observations = %+v, want %+v", report.Observations, wantObservations)
	}
	// Only the suppression beside the workaround comment is a root-cause note;
	// the one with its own reason two lines away is not.
	if want := []Observation{{KindRootCauseNotFixed, "", Location{"pkg/a.go", 4}}}; !reflect.DeepEqual(report.Notes, want) {
		t.Fatalf("notes = %+v, want %+v", report.Notes, want)
	}
	if report.Counts.Suppressions != 2 || report.Counts.WorkaroundComments != 1 || report.Counts.UnreferencedTODOs != 1 || report.Counts.RootCauseNotes != 1 {
		t.Fatalf("counts = %+v", report.Counts)
	}
}

func TestAnalyzeFlagsAbsoluteDirectivesOnlyInAddedRuleFileLines(t *testing.T) {
	head := "# Rules\n\n- NEVER edit generated files\n- Prefer small diffs\n- **Always** run go vet\n- ALWAYS old rule\n"
	input := Input{
		Changes: []Change{{Path: "AGENTS.md", Added: []LineRange{{3, 5}}}, {Path: "README.md", Added: []LineRange{{1, 1}}}},
		Head:    []File{{"AGENTS.md", []byte(head)}, {"README.md", []byte("NEVER do this\n")}},
	}
	report := Analyze(input)
	want := []Observation{
		{KindAbsoluteDirective, "", Location{"AGENTS.md", 3}},
		{KindAbsoluteDirective, "", Location{"AGENTS.md", 5}},
	}
	if !reflect.DeepEqual(report.Observations, want) || report.Counts.AbsoluteDirectives != 2 {
		t.Fatalf("observations = %+v, want %+v", report.Observations, want)
	}
}

func TestAnalyzeIgnoresUnsupportedAndBinaryContent(t *testing.T) {
	input := Input{
		Changes: []Change{{Path: "pkg/a.go", Added: []LineRange{{1, 2}}}, {Path: "notes.txt", Added: []LineRange{{1, 1}}}},
		Head:    []File{{"pkg/a.go", []byte("package pkg\x00\n// TODO: x\n")}, {"notes.txt", []byte("// TODO: x\n")}},
	}
	if report := Analyze(input); len(report.Observations) != 0 || report.Counts != (Counts{}) {
		t.Fatalf("unsupported or binary content produced evidence: %+v", report)
	}
}

func TestAnalyzeIsOrderIndependentAndBounded(t *testing.T) {
	var head strings.Builder
	head.WriteString("package pkg\n")
	for index := 0; index < MaxObservations+10; index++ {
		head.WriteString("// TODO: item\n")
	}
	content := []byte(head.String())
	first := Analyze(Input{Changes: []Change{{Path: "pkg/a.go", Added: []LineRange{{1, 200}}}, {Path: "pkg/b.go", Added: []LineRange{{1, 1}}}}, Head: []File{{"pkg/a.go", content}, {"pkg/b.go", []byte("package pkg\n")}}})
	second := Analyze(Input{Changes: []Change{{Path: "pkg/b.go", Added: []LineRange{{1, 1}}}, {Path: "pkg/a.go", Added: []LineRange{{1, 200}}}}, Head: []File{{"pkg/b.go", []byte("package pkg\n")}, {"pkg/a.go", content}}})
	if !reflect.DeepEqual(first, second) {
		t.Fatal("the report depends on input order")
	}
	if len(first.Observations) != MaxObservations || first.Counts.UnreferencedTODOs != MaxObservations+10 {
		t.Fatalf("bounded list %d, complete count %d", len(first.Observations), first.Counts.UnreferencedTODOs)
	}
}

func TestLexerTracksBlockCommentsAndMultilineStrings(t *testing.T) {
	lines := lexLines(LanguageGo, "a /* b\nc */ d // e\n`raw\n// not a comment\n` f")
	want := []lexedLine{{"a ", " b"}, {" d ", "c  e"}, {"`", ""}, {"", ""}, {"` f", ""}}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("Go lexing = %#v, want %#v", lines, want)
	}
	python := lexLines(LanguagePython, "x = '''\n# not a comment\n'''  # real\n")
	if python[1].comment != "" || python[2].comment != " real" {
		t.Fatalf("Python lexing = %#v", python)
	}
}
