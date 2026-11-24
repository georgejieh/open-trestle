package localreview

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/review"
)

// checkRegressionRun reviews the fixture change with check runs that prove
// one regression, under the given model behaviour.
func checkRegressionRun(t *testing.T, name string, options rmModelFixtureOptions) (Result, review.CheckRuns) {
	t.Helper()
	f := newRmModelFixture(t, options)
	sessionOptions := rmOptions(t, f, rmNewClock())
	runs := walkthroughCheckRuns(t, f.base, f.head)
	sessionOptions.CheckRuns = &runs
	s := rmSession(t, sessionOptions)
	result, err := s.Run(context.Background(), rmPrepare(t, s, f, "check-regression-"+name))
	if err != nil {
		t.Fatal(err)
	}
	return result, runs
}

func renderedResult(t *testing.T, result Result) (string, string, string) {
	t.Helper()
	encoded, err := EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	var text, markdown bytes.Buffer
	if err := RenderResult(&text, result); err != nil {
		t.Fatal(err)
	}
	if err := RenderResultMarkdown(&markdown, result, RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	return string(encoded), text.String(), markdown.String()
}

// A proven regression is reported and blocks when the models find nothing
// and when their answer is invalid, so the review fails.
func TestCheckRegressionIsReportedWhateverTheModelsDid(t *testing.T) {
	for _, test := range []struct {
		name, mode, status, runStatus string
		finished                      bool
	}{
		{"no candidates", "empty", "no_candidates", "succeeded", true},
		{"invalid answer", "malformed", "failed", "failed", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			plain, runs := checkRegressionRun(t, test.mode, rmModelFixtureOptions{generationMode: test.mode})
			if plain.wire.Status != test.status || plain.wire.RunStatus != test.runStatus || plain.wire.CI == "blocked" {
				t.Fatalf("without regressions: status=%s run=%s ci=%s", plain.wire.Status, plain.wire.RunStatus, plain.wire.CI)
			}
			result := WithCheckRegressions(plain, &runs)
			if result.wire.Status != test.status || result.CIDisposition() != "blocked" || result.ExitCode() != 4 || len(result.diagnostics.Findings()) != 0 {
				t.Fatalf("status=%s ci=%s exit=%d", result.wire.Status, result.CIDisposition(), result.ExitCode())
			}
			for policy, want := range map[ExitPolicy]int{ExitPolicyDefault: 4, ExitPolicyFindings: 4, ExitPolicyStrict: 4, ExitPolicyAlwaysZero: 0} {
				if code := result.ExitCodeFor(policy); code != want {
					t.Fatalf("exit for %s = %d, want %d", policy, code, want)
				}
			}
			encoded, text, markdown := renderedResult(t, result)
			if !strings.Contains(encoded, `"ci_disposition":"blocked"`) || !strings.Contains(encoded, `"check_regressions":{"source":"repository_check","count":1,"tests":[{"check":"go test ./calc","test":"example.com/calc.TestAdd"}]}`) {
				t.Fatalf("JSON lacks the regression:\n%s", encoded)
			}
			for _, want := range []string{
				"ci: blocked\n",
				"check regressions: 1 test passed on base and failed on head in the repository's own checks (source: repository check, not a model finding)\ncheck regression: go test ./calc: example.com/calc.TestAdd\n",
			} {
				if !strings.Contains(text, want) {
					t.Fatalf("text lacks %q:\n%s", want, text)
				}
			}
			if !strings.Contains(markdown, "### Check regressions\n\nSource: repository check. 1 test passed on base and failed on head") || !strings.Contains(markdown, "- `go test ./calc`: `example.com/calc.TestAdd`\n") {
				t.Fatalf("Markdown lacks the regression:\n%s", markdown)
			}
			unfinished := "the model review did not finish; these come from the repository's own tests alone"
			if strings.Contains(text, unfinished) == test.finished || strings.Contains(markdown, "The model review did not finish") == test.finished {
				t.Fatalf("did-not-finish note wrong (finished %t):\n%s\n%s", test.finished, text, markdown)
			}
			if report, err := result.Report(); err != nil || report.CheckRegressions == nil || report.CheckRegressions.Count != 1 {
				t.Fatalf("report regressions: %+v %v", report.CheckRegressions, err)
			}
		})
	}
}

// A completed result with regressions imports blocked, and only blocked.
func TestCompletedResultWithCheckRegressionsImportsBlocked(t *testing.T) {
	plain, runs := checkRegressionRun(t, "import", rmModelFixtureOptions{generationMode: "empty"})
	encoded, err := EncodeResult(WithCheckRegressions(plain, &runs))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCompletedResult(encoded)
	if err != nil || parsed.CIDisposition() != "blocked" || parsed.ExitCodeFor(ExitPolicyStrict) != 4 {
		t.Fatalf("parse: %v ci=%s", err, parsed.CIDisposition())
	}
	if _, err := ObserveCompletedResult(encoded); err != nil {
		t.Fatalf("observe: %v", err)
	}
	for name, change := range map[string][2]string{
		"relaxed disposition": {`"ci_disposition":"blocked"`, `"ci_disposition":"inconclusive"`},
		"miscounted":          {`"count":1,"tests"`, `"count":2,"tests"`},
		"unknown source":      {`"source":"repository_check"`, `"source":"model"`},
		"control character":   {`"test":"example.com/calc.TestAdd"`, `"test":"example.com/calc.TestAdd\u001b"`},
	} {
		tampered := []byte(strings.Replace(string(encoded), change[0], change[1], 1))
		if _, err := ParseCompletedResult(tampered); err == nil {
			t.Fatalf("%s: imported", name)
		}
		if _, err := ObserveCompletedResult(tampered); err == nil {
			t.Fatalf("%s: observed", name)
		}
	}
}

// Only regressions of runs that ran count; other outcomes add nothing, and
// the listing is bounded with every regression counted.
func TestCheckRegressionsListOnlyRegressions(t *testing.T) {
	base, head := strings.Repeat("a", 40), strings.Repeat("b", 40)
	none, err := review.NewCheckRuns(base, head, review.CheckRunsChangedOnly, []review.CheckRun{
		{Name: "go test ./a", State: review.CheckRunRan, Tests: 4, NewFailures: []string{"a.TestNew"}, StoppedRunning: []string{"a.TestGone"}, Fixed: 1, StillFailing: 1},
		{Name: "go vet ./a", State: review.CheckRunRan, Tests: 1, NewFailures: []string{"a.go:3: unreachable code"}},
		{Name: "npm test", State: review.CheckRunCouldNotRun, Reason: "missing dependency: jest"},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := emptyResult("failed")
	if NewCheckRegressions(&none) != nil || NewCheckRegressions(nil) != nil || NewCheckRegressions(&review.CheckRuns{}) != nil || WithCheckRegressions(result, &none).CIDisposition() != "error" {
		t.Fatal("outcomes without a regression were reported as regressions")
	}
	var ids []string
	for index := range 20 {
		ids = append(ids, "t.Test"+strings.Repeat("x", index))
	}
	many, err := review.NewCheckRuns(base, head, review.CheckRunsChangedOnly, []review.CheckRun{
		{Name: "go test ./t", State: review.CheckRunRan, Tests: 40, Regressions: ids, RegressionsOmitted: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	value := NewCheckRegressions(&many)
	if value == nil || !value.valid() || value.Count != 23 || len(value.Tests) != maxCheckRegressionTests || value.NotListed != 7 {
		t.Fatalf("regressions = %+v", value)
	}
	text := strings.Join(CheckRegressionsText(value, true), "")
	if !strings.Contains(text, "check regressions: 23 tests passed") || !strings.HasSuffix(text, "check regression: 7 more not listed\n") {
		t.Fatalf("text = %s", text)
	}
	blocked := WithCheckRegressions(result, &many)
	encoded, err := EncodeResult(blocked)
	var wire struct {
		Status           string           `json:"status"`
		CI               string           `json:"ci_disposition"`
		CheckRegressions CheckRegressions `json:"check_regressions"`
	}
	if err != nil || json.Unmarshal(encoded, &wire) != nil || wire.Status != "failed" || wire.CI != "blocked" || wire.CheckRegressions.Count != 23 {
		t.Fatalf("blocked result: %s %v", encoded, err)
	}
	if text, markdown := strings.Join(CheckRegressionsText(nil, false), ""), CheckRegressionsMarkdown(nil, false); text != "" || markdown != "" {
		t.Fatal("no regressions rendered something")
	}
}
