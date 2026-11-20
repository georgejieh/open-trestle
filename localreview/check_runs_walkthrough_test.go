package localreview

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/review"
)

func walkthroughCheckRuns(t *testing.T, base, head string) review.CheckRuns {
	t.Helper()
	runs, err := review.NewCheckRuns(base, head, review.CheckRunsChangedOnly, []review.CheckRun{
		{Name: "go test ./calc", State: review.CheckRunRan, Tests: 5, Regressions: []string{"example.com/calc.TestAdd"}},
		{Name: "go vet ./...", State: review.CheckRunRan},
		{Name: "eslint .", State: review.CheckRunRan, Tests: 2},
		{Name: "npm test", State: review.CheckRunCouldNotRun, Reason: "missing dependency: jest"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return runs
}

// A direct review gives the repository's own check outcomes to the finder
// and the verifier unchanged and shows them as one verified walkthrough line.
func TestDirectReviewCarriesCheckRunsToTheModelsAndTheWalkthrough(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	options := rmOptions(t, f, rmNewClock())
	runs := walkthroughCheckRuns(t, f.base, f.head)
	options.CheckRuns = &runs
	s := rmSession(t, options)
	result, err := s.Run(context.Background(), rmPrepare(t, s, f, "check-runs"))
	if err != nil || result.wire.RunStatus != "succeeded" {
		t.Fatalf("review run: %v status=%s", err, result.wire.RunStatus)
	}
	_, captures := f.generation.snapshot()
	_, verifications := f.verification.snapshot()
	if len(captures) == 0 || len(verifications) == 0 {
		t.Fatal("the review sent no generation or verification request")
	}
	generation, verification := captures[0].Packet, verifications[0].Packet
	if generation.Version != 11 || verification.Version != 10 || !bytes.Contains(generation.CheckRuns, []byte(`"source":"sandboxed_check_runs"`)) || !bytes.Equal(generation.CheckRuns, verification.CheckRuns) {
		t.Fatalf("check_runs: generation v%d %s, verification v%d %s", generation.Version, generation.CheckRuns, verification.Version, verification.CheckRuns)
	}
	walk := result.wire.Walkthrough
	if walk == nil || walk.Verified.CheckRuns == nil {
		t.Fatalf("walkthrough lacks the check runs: %+v", walk)
	}
	if got := *walk.Verified.CheckRuns; got.Scope != review.CheckRunsChangedOnly || got.Runs != 4 || got.Ran != 3 || got.Regressions != 1 || got.NewFailures != 0 || len(got.CouldNotRun) != 1 {
		t.Fatalf("check runs = %+v", got)
	}
	want := "verified: check runs: ran 3 of 4 checks in the sandbox (changed files only; the repository index was unavailable): 1 regression (go test ./calc: example.com/calc.TestAdd), 0 flaky dropped, 1 could not run (npm test: missing dependency: jest)\n"
	if text := strings.Join(WalkthroughText(walk), ""); !strings.Contains(text, want) {
		t.Fatalf("walkthrough text lacks %q:\n%s", want, text)
	}
	wantMarkdown := "- Check runs: ran 3 of 4 checks in the sandbox (changed files only; the repository index was unavailable): 1 regression (`go test ./calc`: `example.com/calc.TestAdd`), 0 flaky dropped, 1 could not run (`npm test`: `missing dependency: jest`).\n"
	if markdown := WalkthroughMarkdown(walk); !strings.Contains(markdown, wantMarkdown) {
		t.Fatalf("walkthrough Markdown lacks %q:\n%s", wantMarkdown, markdown)
	}
	encoded, err := json.Marshal(walk)
	if err != nil || !bytes.Contains(encoded, []byte(`"check_runs":{"scope":"changed_only","runs":4,"ran":3,"regressions":1`)) {
		t.Fatalf("walkthrough JSON = %s, %v", encoded, err)
	}
}

// Without check outcomes nothing is added: neither request carries the
// object and the walkthrough has no line for it.
func TestDirectReviewWithoutCheckRunsAddsNothing(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	s := rmSession(t, rmOptions(t, f, rmNewClock()))
	result, err := s.Run(context.Background(), rmPrepare(t, s, f, "no-check-runs"))
	if err != nil || result.wire.RunStatus != "succeeded" {
		t.Fatalf("review run: %v", err)
	}
	_, captures := f.generation.snapshot()
	_, verifications := f.verification.snapshot()
	if len(captures) == 0 || len(verifications) == 0 || captures[0].Packet.CheckRuns != nil || verifications[0].Packet.CheckRuns != nil {
		t.Fatal("a review without check runs sent check_runs")
	}
	walk := result.wire.Walkthrough
	if walk == nil || walk.Verified.CheckRuns != nil || strings.Contains(strings.Join(WalkthroughText(walk), ""), "check runs") || strings.Contains(WalkthroughMarkdown(walk), "Check runs") {
		t.Fatalf("a review without check runs shows them: %+v", walk)
	}
}

// Outcomes of another range fail the context task instead of reaching a
// model, and an empty value is refused when the session is built.
func TestCheckRunsMustNameTheReviewedRange(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	options := rmOptions(t, f, rmNewClock())
	other := walkthroughCheckRuns(t, f.base, strings.Repeat("3", 40))
	options.CheckRuns = &other
	s := rmSession(t, options)
	result, _ := s.Run(context.Background(), rmPrepare(t, s, f, "other-range"))
	if result.wire.RunStatus == "succeeded" {
		t.Fatal("outcomes of another range were attached")
	}
	if calls, _ := f.generation.snapshot(); calls != 0 {
		t.Fatal("a model request was sent with outcomes of another range")
	}
	empty := rmOptions(t, f, rmNewClock())
	empty.CheckRuns = &review.CheckRuns{}
	if _, err := NewSession(empty); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("an empty check runs value was accepted: %v", err)
	}
}

// An investigation session refuses check runs at creation: its pipeline has
// its own context contract.
func TestInvestigationSessionRefusesCheckRuns(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	options := rmOptions(t, f, rmNewClock())
	policy, err := review.ParseInvestigationPolicy(rmJSON(t, map[string]any{"contract": "open-trestle/investigation-policy", "schema_version": 1, "profile": "snapshot-read-v1", "max_model_turns": 5, "max_tool_calls": 3, "max_returned_bytes": 32768, "max_scanned_bytes": 65536, "max_files": 16, "max_lines_per_read": 20, "max_matches": 8, "max_result_bytes": 8192, "max_cost_micro_usd": 0, "timeout_milliseconds": 5000}))
	if err != nil || validateInvestigationSessionPolicy(options, policy) != nil {
		t.Fatal("the investigation policy is not otherwise valid")
	}
	runs := walkthroughCheckRuns(t, f.base, f.head)
	options.CheckRuns = &runs
	if s, err := NewInvestigationSession(options, policy); s != nil || !errors.Is(err, ErrInvalidSession) {
		if s != nil {
			rmClose(t, s)
		}
		t.Fatalf("an investigation session accepted check runs: %v", err)
	}
	if _, err := options.ObjectsRoot.Stat("."); err != nil {
		t.Fatal("the refused constructor took the caller's root")
	}
	options.CheckRuns = nil
	s, err := NewInvestigationSession(options, policy)
	if err != nil {
		t.Fatalf("the same investigation session without check runs is refused: %v", err)
	}
	rmClose(t, s)
}

// The walkthrough line is bounded: long names are cut, control characters
// replaced, at most three regressions named and the rest counted.
func TestCheckRunsWalkthroughLineIsBounded(t *testing.T) {
	long := "go test " + strings.Repeat("./pkg", 40) + "\x1b[2J"
	runs, err := review.NewCheckRuns(strings.Repeat("a", 40), strings.Repeat("b", 40), review.CheckRunsChangedAndDependents, []review.CheckRun{
		{Name: long, State: review.CheckRunRan, Tests: 9, FlakyDropped: 2, Regressions: []string{"t.A", "t.B", "t.C", "t.D\u202e"}, NewFailures: []string{"t.N"}},
		{Name: "a", State: review.CheckRunCouldNotRun, Reason: "r1"},
		{Name: "b", State: review.CheckRunCouldNotRun, Reason: "r2"},
		{Name: "c", State: review.CheckRunCouldNotRun, Reason: "r3"},
		{Name: "d", State: review.CheckRunCouldNotRun, Reason: "r4"},
		{Name: "e", State: review.CheckRunCouldNotRun, Reason: strings.Repeat("x", 200)},
	})
	if err != nil {
		t.Fatal(err)
	}
	walk := buildWalkthrough(walkthroughInputs{checkRuns: runs}, nil)
	value := walk.Verified.CheckRuns
	if value == nil || walk.validate() != nil || len(value.RegressionTests) != maxWalkthroughCheckRegressions || value.RegressionTestsNotListed != 1 || len(value.CouldNotRun) != maxWalkthroughCheckSkips || value.CouldNotRunNotListed != 1 {
		t.Fatalf("bounded walkthrough = %+v (valid %v)", value, walk.validate())
	}
	name := value.RegressionTests[0].Check
	if !strings.HasSuffix(name, "…") || len([]rune(name)) != maxWalkthroughCheckNameRunes+1 || strings.ContainsRune(name, 0x1b) {
		t.Fatalf("check name was not cut and cleaned: %q", name)
	}
	text := strings.Join(checkRunsText(value, func(s string) string { return s }), "")
	for _, want := range []string{"ran 1 of 6 checks in the sandbox (changed files and their dependents): 4 regressions (", "; go test ./pkg", ": t.C and 1 more), 1 new failing test, 2 flaky dropped, 5 could not run (a: r1; b: r2; c: r3; d: r4 and 1 more)"} {
		if !strings.Contains(text, want) {
			t.Fatalf("line lacks %q: %s", want, text)
		}
	}
	// clone shares nothing with the walkthrough it copies.
	copied := walk.clone()
	copied.Verified.CheckRuns.RegressionTests[0].Test = "changed"
	if walk.Verified.CheckRuns.RegressionTests[0].Test == "changed" {
		t.Fatal("clone shares the regression list")
	}
	// validate rejects an inconsistent or unsafe line.
	for name, mutate := range map[string]func(*WalkthroughCheckRuns){
		"unknown scope":          func(v *WalkthroughCheckRuns) { v.Scope = "everything" },
		"ran past the runs":      func(v *WalkthroughCheckRuns) { v.Ran = v.Runs + 1 },
		"miscounted regressions": func(v *WalkthroughCheckRuns) { v.RegressionTestsNotListed = 0 },
		"miscounted skipped":     func(v *WalkthroughCheckRuns) { v.CouldNotRunNotListed = 0 },
		"control character":      func(v *WalkthroughCheckRuns) { v.CouldNotRun[0].Reason = "r\x1b[2J" },
		"empty test":             func(v *WalkthroughCheckRuns) { v.RegressionTests[0].Test = "" },
		"negative flaky count":   func(v *WalkthroughCheckRuns) { v.FlakyDropped = -1 },
		"too many named failures": func(v *WalkthroughCheckRuns) {
			v.RegressionTests = append(v.RegressionTests, v.RegressionTests[0])
		},
	} {
		broken := walk.clone()
		mutate(broken.Verified.CheckRuns)
		if broken.validate() == nil {
			t.Fatalf("%s: validated", name)
		}
	}
	empty, _ := review.NewCheckRuns(strings.Repeat("a", 40), strings.Repeat("b", 40), review.CheckRunsChangedOnly, nil)
	if lines := checkRunsText(checkRunsWalkthrough(empty), func(s string) string { return s }); len(lines) != 1 || lines[0] != "check runs: no check applies to this change" {
		t.Fatalf("no-runs line = %q", lines)
	}
}
