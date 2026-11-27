package localreview

import (
	"context"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/review"
)

// modelCheckRun reviews the fixture change with check runs; authoring adds
// the test authoring request.
func modelCheckRun(t *testing.T, name string, authoring bool) (Result, []review.AuthoredCheck, int) {
	t.Helper()
	f := newRmModelFixture(t, rmModelFixtureOptions{verificationMode: "check"})
	sessionOptions := rmOptions(t, f, rmNewClock())
	runs := walkthroughCheckRuns(t, f.base, f.head)
	if authoring {
		var err error
		if runs, err = runs.WithTestAuthoring([]string{review.TestFrameworkGo}); err != nil {
			t.Fatal(err)
		}
	}
	sessionOptions.CheckRuns = &runs
	s := rmSession(t, sessionOptions)
	result, err := s.Run(context.Background(), rmPrepare(t, s, f, "model-check-"+name))
	if err != nil {
		t.Fatal(err)
	}
	checks, dropped := s.AuthoredChecks()
	return result, checks, dropped
}

// The checker's check reaches the session only when the check runs asked
// for one, and it names the verified finding it demonstrates.
func TestSessionCollectsTheCheckerChecksOnlyWhenAsked(t *testing.T) {
	result, checks, dropped := modelCheckRun(t, "asked", true)
	report, err := result.Report()
	if err != nil || report.Status != "findings" || len(report.Findings) != 1 {
		t.Fatalf("report %+v %v", report, err)
	}
	if dropped != 0 || len(checks) != 1 || checks[0].FindingIdentity != report.Findings[0].SourceIdentity || checks[0].Framework != review.TestFrameworkGo || checks[0].Content != "package calc\n" || checks[0].Path != report.Findings[0].Path {
		t.Fatalf("checks %+v dropped %d", checks, dropped)
	}
	if _, checks, dropped := modelCheckRun(t, "not-asked", false); checks != nil || dropped != 0 {
		t.Fatalf("unasked checks %+v %d", checks, dropped)
	}
}

func TestModelWrittenChecksLeaveTheResultStandingAndRoundTrip(t *testing.T) {
	plain, _, _ := modelCheckRun(t, "result", true)
	report, err := plain.Report()
	if err != nil {
		t.Fatal(err)
	}
	finding := report.Findings[0]
	kept := ModelWrittenCheck{FindingIdentity: finding.Identity, Status: ModelCheckRegression, Framework: review.TestFrameworkGo, Path: "calc/trestle_check_1_test.go", Content: "package calc\n", Tests: []string{"example.com/calc.TestTrestle"}}
	other := kept
	other.FindingIdentity = strings.Repeat("e", 64)
	result := WithModelWrittenChecks(plain, NewModelWrittenChecks([]ModelWrittenCheck{kept, other}, 1))
	if result.wire.Status != plain.wire.Status || result.CIDisposition() != plain.CIDisposition() || result.ExitCode() != plain.ExitCode() {
		t.Fatal("model-written checks changed the result's standing")
	}
	encoded, text, markdown := renderedResult(t, result)
	if !strings.Contains(encoded, `"model_written_checks":{"source":"model_written_check","kept":[{"finding_identity":"`+finding.Identity+`","status":"regression","framework":"go_test","path":"calc/trestle_check_1_test.go","content":"package calc\n","tests":["example.com/calc.TestTrestle"]}],"discarded":2}`) {
		t.Fatalf("JSON lacks the checks:\n%s", encoded)
	}
	if !strings.Contains(text, "model-written checks: 1 kept, 2 discarded") || !strings.Contains(text, "model-written check: \""+finding.Title+"\" (") || strings.Contains(text, "package calc") {
		t.Fatalf("text:\n%s", text)
	}
	if !strings.Contains(markdown, "### Model-written checks") || !strings.Contains(markdown, "`calc/trestle_check_1_test.go`") || strings.Contains(markdown, "package calc") {
		t.Fatalf("Markdown:\n%s", markdown)
	}
	if got, err := result.Report(); err != nil || got.ModelWrittenChecks == nil || len(got.ModelWrittenChecks.Kept) != 1 {
		t.Fatalf("report %+v %v", got.ModelWrittenChecks, err)
	}
	parsed, err := ParseCompletedResult([]byte(encoded))
	if err != nil || parsed.CIDisposition() != plain.CIDisposition() {
		t.Fatalf("parse: %v", err)
	}
	for name, change := range map[string][2]string{
		"unknown finding": {`"finding_identity":"` + finding.Identity, `"finding_identity":"` + strings.Repeat("e", 64)},
		"status":          {`"status":"regression"`, `"status":"maybe"`},
		"path":            {`"path":"calc/trestle_check_1_test.go"`, `"path":"calc/other_test.go"`},
		"no tests":        {`"tests":["example.com/calc.TestTrestle"]`, `"tests":[]`},
		"source":          {`"source":"model_written_check"`, `"source":"model"`},
	} {
		if _, err := ParseCompletedResult([]byte(strings.Replace(encoded, change[0], change[1], 1))); err == nil {
			t.Errorf("%s: imported", name)
		}
	}
	if WithModelWrittenChecks(plain, nil).wire.ModelWrittenChecks != nil || NewModelWrittenChecks(nil, 0) != nil {
		t.Fatal("no checks added a block")
	}
}
