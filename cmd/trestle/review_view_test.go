package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/localreview"
)

// The text document a script reads from `trestle review`, pinned for the
// general review and for the default specialist set of the offline fixture.
const (
	reviewPlainEvidence = "evidence: 8d0ff8ec7334f5ca6ce109719eb841cfdf1d435ccd4cb4e5fee4717000ccfe69, f84bfca8f400a5604197baaa59ed97fe16cd0fd11d90cec3a5eb683334594e75\n"
	reviewPlainSingle   = "status: findings\nci: blocked\nrun: succeeded\nwalkthrough:\n" +
		"verified: secret scan: 2 model requests scanned before sending (306 bytes, 0 secret matches)\n" +
		"verified: static check static_debug_output: passed (1 file checked, 0 matches)\n" +
		"verified: pattern hygiene: 0 added suppressions, 0 added workaround comments, 0 spreading anti-patterns\n" +
		"verified: style detection: ran (1 recommendation, 0 withheld)\n" +
		"verified: semantic impact: 1 changed declaration, 0 public API changes, 1 reference (0 from tests), 0 gaps\n" +
		"verified: context used: 0 enclosing definitions, 1 caller, 0 tests, 0 map entries; budget 60 KiB (route window)\n" +
		"verified: independent verifier (distinct_model): 1 of 1 candidate confirmed, 0 rejected, 0 inconclusive\n" +
		"stated intent (author-stated, unverified): \"change\"\n" +
		"file: a.go modified +1 -1; changed function Changed\n" +
		"missing verification: no test file references the changed function Changed (a.go)\n" +
		"confirmed findings (ranked): 1\nfinding: error Zero-valued caller now panics\nrank: 1\nsource: a.go:2-2\n" +
		"message: Consume passes zero to Changed after removal of the division guard.\n" + reviewPlainEvidence +
		"category: correctness\n" +
		"coverage: candidates=1 verified=1 rejected=0 inconclusive=0\n" +
		"source coverage: analyzed=2 selected=2 omitted=0\n" +
		"tokens: input=240 output=160 cached_input=0 over 2 route attempts\n" +
		"style: no declared Go style for 1 changed file; consider gofmt and Effective Go, and commit its configuration\n" +
		"comprehensive clearance: false\n"
	reviewPlainSet = "status: findings\nci: blocked\nreviewers: general, bug_hunter, backend, drift_auditor (4 of 4 ran)\nwalkthrough:\n" +
		"verified: secret scan: 8 model requests from 4 reviewers scanned before sending (1224 bytes, 0 secret matches)\n" +
		"verified: static check static_debug_output: passed (1 file checked, 0 matches)\n" +
		"verified: pattern hygiene: 0 added suppressions, 0 added workaround comments, 0 spreading anti-patterns\n" +
		"verified: style detection: ran (1 recommendation, 0 withheld)\n" +
		"verified: semantic impact: 1 changed declaration, 0 public API changes, 1 reference (0 from tests), 0 gaps\n" +
		"verified: context used: 0 enclosing definitions, 1 caller, 0 tests, 0 map entries; budget 60 KiB (route window)\n" +
		"verified: independent verifier (distinct_model): 4 of 4 candidates from 4 reviewers confirmed, 0 rejected, 0 inconclusive\n" +
		"stated intent (author-stated, unverified): \"change\"\n" +
		"file: a.go modified +1 -1; changed function Changed\n" +
		"missing verification: no test file references the changed function Changed (a.go)\n" +
		"confirmed findings (ranked): 1\nfinding: error Zero-valued caller now panics\nrank: 1\nsource: a.go:2-2\n" +
		"message: Consume passes zero to Changed after removal of the division guard.\n" + reviewPlainEvidence +
		"category: correctness\nconfirmed by: general, bug_hunter, backend, drift_auditor\n" +
		"tokens: input=960 output=640 cached_input=0 over 8 route attempts (4 reviewers)\n" +
		"style: no declared Go style for 1 changed file; consider gofmt and Effective Go, and commit its configuration\n" +
		"comprehensive clearance: false\n"
)

// runReviewOnTerminal runs `trestle review` with standard output, and only
// it, treated as a terminal.
func runReviewOnTerminal(t *testing.T, checkout string, args ...string) (int, string, string) {
	t.Helper()
	t.Chdir(checkout)
	var stdout, stderr bytes.Buffer
	previous := initTerminal
	initTerminal = func(w io.Writer) bool { return w == &stdout }
	t.Cleanup(func() { initTerminal = previous })
	code := run(append([]string{"review"}, args...), &stdout, &stderr)
	initTerminal = previous
	return code, stdout.String(), stderr.String()
}

func TestReviewTextForScriptsIsUnchanged(t *testing.T) {
	for _, test := range []struct {
		name  string
		extra []string
		want  string
	}{
		{"general review", []string{"--specialists", "none"}, reviewPlainSingle},
		{"specialist set", nil, reviewPlainSet},
	} {
		t.Run(test.name, func(t *testing.T) {
			checkout := latestChangeCheckout(t)
			latestChangeSetupWith(t, checkout, test.extra...)
			latestFixtureTransport(t)
			code, stdout, stderr := runReviewCommand(t, checkout)
			if code != 4 || stdout != test.want {
				t.Fatalf("exit=%d\n%s\nwant\n%s", code, stdout, test.want)
			}
			if !initHas(stderr, "Review finished: 1 confirmed finding.") {
				t.Fatalf("the verdict left standard error:\n%s", stderr)
			}
		})
	}
}

func TestReviewOnATerminalStartsWithTheVerdict(t *testing.T) {
	checkout := latestChangeCheckout(t)
	latestChangeSetupWith(t, checkout)
	latestFixtureTransport(t)
	initColorEnv(t, "xterm-256color", "")
	t.Setenv("NO_COLOR", "1")
	code, stdout, stderr := runReviewOnTerminal(t, checkout)
	want := "\n" +
		"  ✗ 1 confirmed finding · CI blocked (exit 4)\n" +
		"    4 of 4 reviewers ran: general, bug_hunter, backend,\n" +
		"    drift_auditor\n" +
		"\n" +
		"  1. error  Zero-valued caller now panics\n" +
		"     a.go:2-2 · correctness · confirmed by general,\n" +
		"     bug_hunter, backend, drift_auditor\n" +
		"     Consume passes zero to Changed after removal of the\n" +
		"     division guard.\n" +
		"\n" +
		"  Checked:  secret scan clean · checker confirmed 4 of 4\n" +
		"            candidates · 1 changed function without a test\n" +
		"  Not a complete audit. Details: trestle review --verbose\n"
	if code != 4 || stdout != want {
		t.Fatalf("exit=%d\n%s\nwant\n%s", code, stdout, want)
	}
	if initHas(stderr, "Review finished") || initHas(stdout, "status: findings") {
		t.Fatalf("the verdict was printed twice or the document was kept:\n%s", stderr)
	}
	initAssertWidth(t, stdout)
	// --verbose keeps the full text, and every other format is unchanged.
	if code, stdout, stderr = runReviewOnTerminal(t, checkout, "--verbose"); code != 4 || !strings.HasPrefix(stdout, "status: findings\n") || !initHas(stderr, "Review finished") {
		t.Fatalf("--verbose: exit=%d\n%s\n%s", code, stdout, stderr)
	}
	var result map[string]any
	if code, stdout, _ = runReviewOnTerminal(t, checkout, "--format", "json"); code != 4 || json.Unmarshal([]byte(stdout), &result) != nil {
		t.Fatalf("--format json: exit=%d %s", code, stdout)
	}
	if code, stdout, _ = runReviewOnTerminal(t, checkout, "--format", "markdown"); code != 4 || !strings.HasPrefix(stdout, "## Open Trestle review\n") {
		t.Fatalf("--format markdown: exit=%d %s", code, stdout)
	}
}

func TestReviewViewColorsTheSeverity(t *testing.T) {
	checkout := latestChangeCheckout(t)
	latestChangeSetupWith(t, checkout, "--specialists", "none")
	latestFixtureTransport(t)
	initColorEnv(t, "xterm-256color", "")
	code, stdout, _ := runReviewOnTerminal(t, checkout)
	if code != 4 || !strings.Contains(stdout, "  1. \x1b[38;5;131merror\x1b[0m  Zero-valued caller now panics\n") || !strings.Contains(stdout, "\x1b[38;5;131m✗\x1b[0m 1 confirmed finding") {
		t.Fatalf("exit=%d\n%q", code, stdout)
	}
}

func TestReviewViewNamesRegressionsAndUnfinishedReviewers(t *testing.T) {
	initAsTerminal(t)
	initColorEnv(t, "dumb", "")
	var out bytes.Buffer
	view := &reviewView{status: "no_candidates", ci: "blocked", selected: 3, reviewers: []string{"general", "backend"}, set: true,
		unfinished: []reviewViewMember{
			{launched: true, member: "backend", text: "failed: internal (task verification): model_output_exhausted", hint: "choose a non-reasoning model for this role"},
			{member: "security_probe", text: "the review was canceled"},
		},
		regressions: &localreview.CheckRegressions{Count: 3, Tests: []localreview.CheckRegression{{Check: "go test ./a", Test: "TestA\x1b[2J"}}, NotListed: 2}}
	view.render(newOutPrinter(t.Context(), &out), 4, localreview.RenderOptions{})
	want := "\n" +
		"  [x] No model finding, but check regressions · CI blocked\n" +
		"      (exit 4)\n" +
		"    2 of 3 reviewers ran: general, backend\n" +
		"  [..] backend did not finish: failed: internal (task\n" +
		"       verification): model_output_exhausted\n" +
		"    choose a non-reasoning model for this role\n" +
		"  [--] security_probe did not run: the review was canceled\n" +
		"\n" +
		"  [x] 3 check regressions: tests that passed on base fail on\n" +
		"      head\n" +
		"    From the repository's own checks, not a model finding.\n" +
		"    go test ./a: TestA?[2J\n" +
		"    2 more not listed\n" +
		"    The model review did not finish; these come from the\n" +
		"    repository's own tests alone.\n" +
		"\n" +
		"  Not a complete audit. Details: trestle review --verbose\n"
	if out.String() != want {
		t.Fatalf("\n%s\nwant\n%s", out.String(), want)
	}
}
