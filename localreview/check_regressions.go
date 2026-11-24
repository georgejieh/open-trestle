package localreview

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/georgejieh/open-trestle/internal/review"
)

// Check regressions are the tests that the repository's own checks proved
// broken: each passed in both base runs and failed in both head runs in the
// sandbox. They come from the host's runs, never from a model answer, so a
// result reports them and blocks CI whatever the models did, including when
// the model review did not finish. They are not verified findings.

// CheckRegressionsSource labels every check regression.
const CheckRegressionsSource = "repository_check"

// maxCheckRegressionTests bounds the listed regressions; Count covers all.
const maxCheckRegressionTests = 16

// CheckRegressions lists the proven test regressions of a review. Count is
// every regression the checks reported, Tests the first ones and NotListed
// the rest. Check names and test IDs are repository text, cut and with
// control and format characters replaced as the walkthrough shows them.
type CheckRegressions struct {
	Source    string            `json:"source"`
	Count     int               `json:"count"`
	Tests     []CheckRegression `json:"tests"`
	NotListed int               `json:"not_listed,omitempty"`
}

// CheckRegression is one regression: the check that ran and the test ID.
type CheckRegression struct {
	Check string `json:"check"`
	Test  string `json:"test"`
}

// NewCheckRegressions collects the regressions of runs; nil when there are
// none.
func NewCheckRegressions(runs *review.CheckRuns) *CheckRegressions {
	if runs == nil || runs.IsZero() {
		return nil
	}
	value := &CheckRegressions{Source: CheckRegressionsSource, Tests: []CheckRegression{}}
	for _, run := range runs.Runs() {
		if run.State != review.CheckRunRan {
			continue
		}
		value.Count += len(run.Regressions) + run.RegressionsOmitted
		for _, test := range run.Regressions {
			if len(value.Tests) < maxCheckRegressionTests {
				value.Tests = append(value.Tests, CheckRegression{Check: displayText(run.Name, maxWalkthroughCheckNameRunes), Test: displayText(test, maxWalkthroughCheckTestRunes)})
			}
		}
	}
	if value.Count == 0 {
		return nil
	}
	value.NotListed = value.Count - len(value.Tests)
	return value
}

func (c *CheckRegressions) clone() *CheckRegressions {
	if c == nil {
		return nil
	}
	value := *c
	value.Tests = append([]CheckRegression{}, c.Tests...)
	return &value
}

func (c *CheckRegressions) valid() bool {
	if c == nil {
		return true
	}
	if c.Source != CheckRegressionsSource || c.Tests == nil || len(c.Tests) > maxCheckRegressionTests || c.NotListed < 0 || c.Count < 1 || c.Count != len(c.Tests)+c.NotListed {
		return false
	}
	for _, test := range c.Tests {
		if test.Check == "" || displayText(test.Check, maxWalkthroughCheckNameRunes) != test.Check || test.Test == "" || displayText(test.Test, maxWalkthroughCheckTestRunes) != test.Test {
			return false
		}
	}
	return true
}

// WithCheckRegressions adds the regressions of runs to a result and makes its
// CI disposition blocked; its status and findings stay the models'. When the
// result would pass its output bounds, the walkthrough is left out first and
// then listed tests, so the regressions are never dropped. A result without
// regressions is returned as it is.
func WithCheckRegressions(result Result, runs *review.CheckRuns) Result {
	regressions := NewCheckRegressions(runs)
	if !result.valid || regressions == nil {
		return result
	}
	result.sealedJSON, result.sealedText = nil, nil
	result.wire.CI = "blocked"
	fits := func(candidate Result) bool {
		var text, markdown bytes.Buffer
		_, err := EncodeResult(candidate)
		return err == nil && RenderResultWithOptions(&text, candidate, maximalText) == nil && RenderResultMarkdown(&markdown, candidate, maximalText) == nil
	}
	for {
		with := result
		with.wire.CheckRegressions = regressions
		if fits(with) {
			return with
		}
		switch {
		case result.wire.Walkthrough != nil:
			result.wire.Walkthrough = nil
			result.wire.Limitations = append(append([]string{}, result.wire.Limitations...), walkthroughOmittedLimitation)
		case len(regressions.Tests) > 0:
			regressions = regressions.clone()
			regressions.Tests = regressions.Tests[:len(regressions.Tests)-1]
			regressions.NotListed++
		default:
			return with
		}
	}
}

// CheckRegressionsText words the regressions as text lines; finished is
// false when the model review did not finish.
func CheckRegressionsText(c *CheckRegressions, finished bool) []string {
	if c == nil {
		return nil
	}
	lines := []string{fmt.Sprintf("check regressions: %d test%s passed on base and failed on head in the repository's own checks (source: repository check, not a model finding)\n", c.Count, plural(c.Count))}
	for _, test := range c.Tests {
		lines = append(lines, "check regression: "+test.Check+": "+test.Test+"\n")
	}
	if c.NotListed > 0 {
		lines = append(lines, fmt.Sprintf("check regression: %d more not listed\n", c.NotListed))
	}
	if !finished {
		lines = append(lines, "check regressions: the model review did not finish; these come from the repository's own tests alone\n")
	}
	return lines
}

// CheckRegressionsMarkdown renders the regressions as a Markdown section;
// finished is false when the model review did not finish.
func CheckRegressionsMarkdown(c *CheckRegressions, finished bool) string {
	if c == nil {
		return ""
	}
	var buffer strings.Builder
	fmt.Fprintf(&buffer, "### Check regressions\n\nSource: repository check. %d test%s passed on base and failed on head when the repository's own checks ran in the sandbox. These are not model findings.\n\n", c.Count, plural(c.Count))
	for _, test := range c.Tests {
		buffer.WriteString("- " + MarkdownCode(test.Check) + ": " + MarkdownCode(test.Test) + "\n")
	}
	if c.NotListed > 0 {
		fmt.Fprintf(&buffer, "- %d more, not listed.\n", c.NotListed)
	}
	if !finished {
		buffer.WriteString("\nThe model review did not finish; these regressions come from the repository's own tests alone.\n")
	}
	return buffer.String()
}
