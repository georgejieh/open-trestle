package repochecks

import (
	"fmt"
	"strings"
)

// Summary is the walkthrough's "what ran" line.
func (report Report) Summary() string {
	if len(report.Results) == 0 {
		return "no checks apply to this change"
	}
	ran, regressions, newFailures, stopped, fixed, stillFailing, flaky := 0, 0, 0, 0, 0, 0, 0
	var skipped []string
	for _, result := range report.Results {
		if !result.Ran {
			skipped = append(skipped, result.Name+": "+result.Reason)
			continue
		}
		ran++
		regressions += len(result.Regressions)
		newFailures += len(result.NewFailures)
		stopped += len(result.StoppedRunning)
		fixed += result.Fixed
		stillFailing += result.StillFailing
		flaky += result.Flaky
	}
	parts := []string{plural(regressions, "regression", "regressions")}
	for _, count := range []struct {
		value int
		text  string
	}{{newFailures, "new failing"}, {stopped, "stopped running"}, {fixed, "fixed"}, {stillFailing, "still failing"}} {
		if count.value > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", count.value, count.text))
		}
	}
	parts = append(parts, fmt.Sprintf("%d flaky dropped", flaky))
	if len(skipped) > 0 {
		parts = append(parts, fmt.Sprintf("%d could not run (%s)", len(skipped), strings.Join(skipped, "; ")))
	}
	return fmt.Sprintf("ran %d of %d checks in the sandbox: %s", ran, len(report.Results), strings.Join(parts, ", "))
}

func plural(count int, one, many string) string {
	if count == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", count, many)
}
