package localreview

import (
	"fmt"
	"strings"

	"github.com/georgejieh/open-trestle/internal/review"
)

// Check-runs listing bounds, in characters for text.
const (
	maxWalkthroughCheckNameRunes   = 80
	maxWalkthroughCheckReasonRunes = 120
	maxWalkthroughCheckTestRunes   = 120
	maxWalkthroughCheckRegressions = 3
	maxWalkthroughCheckSkips       = 4
)

// WalkthroughCheckRuns summarizes the repository's own checks, run in the
// sandbox on base and head, as the run's generation context carried them.
// Runs counts the listed runs and RunsNotListed those past the context's
// bound. Scope is review.CheckRunsChangedAndDependents or
// review.CheckRunsChangedOnly. RegressionTests names the first regressions and
// CouldNotRun the first runs that could not run; the NotListed counts cover
// the rest. Names, reasons and test IDs are repository text: control and
// format characters are replaced, each is cut, and renderers escape them.
type WalkthroughCheckRuns struct {
	Scope                    string                 `json:"scope"`
	Runs                     int                    `json:"runs"`
	RunsNotListed            int                    `json:"runs_not_listed,omitempty"`
	Ran                      int                    `json:"ran"`
	Regressions              int                    `json:"regressions"`
	NewFailures              int                    `json:"new_failures"`
	FlakyDropped             int                    `json:"flaky_dropped"`
	RegressionTests          []WalkthroughCheckTest `json:"regression_tests"`
	RegressionTestsNotListed int                    `json:"regression_tests_not_listed,omitempty"`
	CouldNotRun              []WalkthroughCheckSkip `json:"could_not_run"`
	CouldNotRunNotListed     int                    `json:"could_not_run_not_listed,omitempty"`
}

// WalkthroughCheckTest is one regression: the run and the test ID.
type WalkthroughCheckTest struct {
	Check string `json:"check"`
	Test  string `json:"test"`
}

// WalkthroughCheckSkip is one run that could not run, with the reason.
type WalkthroughCheckSkip struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// checkRunsWalkthrough summarizes a recorded context's check runs; the zero
// value means the context carried none.
func checkRunsWalkthrough(runs review.CheckRuns) *WalkthroughCheckRuns {
	if runs.IsZero() {
		return nil
	}
	listed := runs.Runs()
	value := &WalkthroughCheckRuns{Scope: runs.Scope(), Runs: len(listed), RunsNotListed: runs.RunsOmitted(), RegressionTests: []WalkthroughCheckTest{}, CouldNotRun: []WalkthroughCheckSkip{}}
	for _, run := range listed {
		name := displayText(run.Name, maxWalkthroughCheckNameRunes)
		if run.State != review.CheckRunRan {
			if len(value.CouldNotRun) == maxWalkthroughCheckSkips {
				value.CouldNotRunNotListed++
				continue
			}
			value.CouldNotRun = append(value.CouldNotRun, WalkthroughCheckSkip{Check: name, Reason: displayText(run.Reason, maxWalkthroughCheckReasonRunes)})
			continue
		}
		value.Ran++
		value.Regressions += len(run.Regressions) + run.RegressionsOmitted
		value.NewFailures += len(run.NewFailures) + run.NewFailuresOmitted
		value.FlakyDropped += run.FlakyDropped
		for _, test := range run.Regressions {
			if len(value.RegressionTests) < maxWalkthroughCheckRegressions {
				value.RegressionTests = append(value.RegressionTests, WalkthroughCheckTest{Check: name, Test: displayText(test, maxWalkthroughCheckTestRunes)})
			}
		}
	}
	value.RegressionTestsNotListed = value.Regressions - len(value.RegressionTests)
	return value
}

func (w *WalkthroughCheckRuns) clone() *WalkthroughCheckRuns {
	if w == nil {
		return nil
	}
	value := *w
	value.RegressionTests = append([]WalkthroughCheckTest{}, w.RegressionTests...)
	value.CouldNotRun = append([]WalkthroughCheckSkip{}, w.CouldNotRun...)
	return &value
}

func (w *WalkthroughCheckRuns) valid() bool {
	if w == nil {
		return true
	}
	for _, count := range []int{w.Runs, w.RunsNotListed, w.Ran, w.Regressions, w.NewFailures, w.FlakyDropped, w.RegressionTestsNotListed, w.CouldNotRunNotListed} {
		if count < 0 {
			return false
		}
	}
	if w.Scope != review.CheckRunsChangedAndDependents && w.Scope != review.CheckRunsChangedOnly ||
		w.Ran > w.Runs || w.RegressionTests == nil || w.CouldNotRun == nil || len(w.RegressionTests) > maxWalkthroughCheckRegressions || len(w.CouldNotRun) > maxWalkthroughCheckSkips ||
		w.RegressionTestsNotListed != w.Regressions-len(w.RegressionTests) || len(w.CouldNotRun)+w.CouldNotRunNotListed != w.Runs-w.Ran {
		return false
	}
	shown := func(text string, limit int) bool { return text != "" && displayText(text, limit) == text }
	for _, test := range w.RegressionTests {
		if !shown(test.Check, maxWalkthroughCheckNameRunes) || !shown(test.Test, maxWalkthroughCheckTestRunes) {
			return false
		}
	}
	for _, skip := range w.CouldNotRun {
		if !shown(skip.Check, maxWalkthroughCheckNameRunes) || !shown(skip.Reason, maxWalkthroughCheckReasonRunes) {
			return false
		}
	}
	return true
}

// checkRunsText words what ran: how many runs ran and on what scope, the
// regressions with the first ones named, new failures when there are any,
// flaky tests dropped, and the runs that could not run with their reasons.
func checkRunsText(runs *WalkthroughCheckRuns, code func(string) string) []string {
	if runs == nil {
		return nil
	}
	if runs.Runs == 0 && runs.RunsNotListed == 0 {
		return []string{"check runs: no check applies to this change"}
	}
	named := func(names []string, more int) string {
		text := strings.Join(names, "; ")
		if more > 0 {
			text += fmt.Sprintf(" and %d more", more)
		}
		return " (" + text + ")"
	}
	regressions := fmt.Sprintf("%d regression%s", runs.Regressions, plural(runs.Regressions))
	if len(runs.RegressionTests) > 0 {
		names := make([]string, len(runs.RegressionTests))
		for index, test := range runs.RegressionTests {
			names[index] = code(test.Check) + ": " + code(test.Test)
		}
		regressions += named(names, runs.RegressionTestsNotListed)
	}
	parts := []string{regressions}
	if runs.NewFailures > 0 {
		parts = append(parts, fmt.Sprintf("%d new failing test%s", runs.NewFailures, plural(runs.NewFailures)))
	}
	parts = append(parts, fmt.Sprintf("%d flaky dropped", runs.FlakyDropped))
	if skipped := runs.Runs - runs.Ran; skipped > 0 {
		names := make([]string, len(runs.CouldNotRun))
		for index, skip := range runs.CouldNotRun {
			names[index] = code(skip.Check) + ": " + code(skip.Reason)
		}
		parts = append(parts, fmt.Sprintf("%d could not run", skipped)+named(names, runs.CouldNotRunNotListed))
	}
	scope := "changed files and their dependents"
	if runs.Scope == review.CheckRunsChangedOnly {
		scope = "changed files only; the repository index was unavailable"
	}
	text := fmt.Sprintf("check runs: ran %d of %d check%s in the sandbox (%s): %s", runs.Ran, runs.Runs, plural(runs.Runs), scope, strings.Join(parts, ", "))
	if runs.RunsNotListed > 0 {
		text += fmt.Sprintf("; %d more check%s not listed", runs.RunsNotListed, plural(runs.RunsNotListed))
	}
	return []string{text}
}
