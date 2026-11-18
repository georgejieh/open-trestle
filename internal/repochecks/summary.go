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
	ran, regressions, flaky := 0, 0, 0
	var skipped []string
	for _, result := range report.Results {
		if !result.Ran {
			skipped = append(skipped, result.Name+": "+result.Reason)
			continue
		}
		ran++
		regressions += len(result.Regressions)
		flaky += result.Flaky
	}
	parts := []string{plural(regressions, "regression", "regressions"), fmt.Sprintf("%d flaky dropped", flaky)}
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
