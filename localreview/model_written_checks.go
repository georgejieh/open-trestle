package localreview

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/review"
)

// Model-written checks are tests the checker wrote for its verified findings
// and the host ran in the sandbox, keeping only those that showed a
// regression. The model controls the test's output, so a kept check never
// changes a result's status, CI disposition or exit code; it only shows
// which finding a test demonstrates.

// ModelWrittenChecksSource labels every model-written check.
const ModelWrittenChecksSource = "model_written_check"

// Kept statuses: a test that passed twice on base and failed twice on head,
// and one that base could not build and that failed twice on head.
const (
	ModelCheckRegression  = "regression"
	ModelCheckFailsOnHead = "fails_on_head"
)

const maxModelCheckTests = 16

// ModelWrittenChecks lists the kept checks of a review; Discarded counts the
// checks the checker wrote that were dropped, failed validation or did not
// show a regression.
type ModelWrittenChecks struct {
	Source    string              `json:"source"`
	Kept      []ModelWrittenCheck `json:"kept"`
	Discarded int                 `json:"discarded"`
}

// ModelWrittenCheck is one kept test: the diagnostic finding it demonstrates,
// the path the host gave it, its text, and the test IDs that failed on head.
type ModelWrittenCheck struct {
	FindingIdentity string   `json:"finding_identity"`
	Status          string   `json:"status"`
	Framework       string   `json:"framework"`
	Path            string   `json:"path"`
	Content         string   `json:"content"`
	Tests           []string `json:"tests"`
}

var modelCheckName = regexp.MustCompile(`^(trestle_check_[1-9][0-9]*_test\.go|test_trestle_check_[1-9][0-9]*\.py)$`)

// NewModelWrittenChecks bounds the kept checks for a result: the path and
// test IDs as the walkthrough shows repository text, at most 16 test IDs
// each. It is nil when the checker wrote no check.
func NewModelWrittenChecks(kept []ModelWrittenCheck, discarded int) *ModelWrittenChecks {
	if len(kept) == 0 && discarded == 0 {
		return nil
	}
	value := &ModelWrittenChecks{Source: ModelWrittenChecksSource, Kept: []ModelWrittenCheck{}, Discarded: discarded}
	for _, check := range kept {
		check.Path = displayText(check.Path, maxWalkthroughCheckTestRunes)
		tests := []string{}
		for _, test := range check.Tests[:min(len(check.Tests), maxModelCheckTests)] {
			tests = append(tests, displayText(test, maxWalkthroughCheckTestRunes))
		}
		check.Tests = tests
		value.Kept = append(value.Kept, check)
	}
	return value
}

func (c *ModelWrittenChecks) clone() *ModelWrittenChecks {
	if c == nil {
		return nil
	}
	value := *c
	value.Kept = make([]ModelWrittenCheck, len(c.Kept))
	for index, check := range c.Kept {
		check.Tests = append([]string{}, check.Tests...)
		value.Kept[index] = check
	}
	return &value
}

// valid checks the block's bounds; reported says whether a diagnostic
// finding identity is one of the result's.
func (c *ModelWrittenChecks) valid(reported func(string) bool) bool {
	if c == nil {
		return true
	}
	if c.Source != ModelWrittenChecksSource || c.Kept == nil || len(c.Kept) > review.MaxAuthoredChecks || c.Discarded < 0 || c.Discarded > 1<<16 || len(c.Kept)+c.Discarded == 0 {
		return false
	}
	for _, check := range c.Kept {
		if !reported(check.FindingIdentity) || check.Status != ModelCheckRegression && check.Status != ModelCheckFailsOnHead ||
			check.Framework != review.TestFrameworkGo && check.Framework != review.TestFrameworkPytest && check.Framework != review.TestFrameworkUnittest ||
			displayText(check.Path, maxWalkthroughCheckTestRunes) != check.Path || !modelCheckName.MatchString(path.Base(check.Path)) ||
			len(check.Content) > review.MaxAuthoredCheckBytes || !utf8.ValidString(check.Content) || strings.ContainsRune(check.Content, 0) || strings.TrimSpace(check.Content) == "" ||
			len(check.Tests) == 0 || len(check.Tests) > maxModelCheckTests {
			return false
		}
		for _, test := range check.Tests {
			if test == "" || displayText(test, maxWalkthroughCheckTestRunes) != test {
				return false
			}
		}
	}
	return true
}

// WithModelWrittenChecks adds the checks to a result without changing its
// status, CI disposition or exit code. A kept check of a finding the result
// does not report, or one that would pass the result's output bounds, is
// counted as discarded instead.
func WithModelWrittenChecks(result Result, checks *ModelWrittenChecks) Result {
	if !result.valid || checks == nil {
		return result
	}
	reported := map[string]bool{}
	for _, finding := range result.diagnostics.Findings() {
		reported[finding.Identity()] = true
	}
	value := checks.clone()
	value.Kept = value.Kept[:0]
	for _, check := range checks.Kept {
		if reported[check.FindingIdentity] && len(value.Kept) < review.MaxAuthoredChecks {
			value.Kept = append(value.Kept, check)
		} else {
			value.Discarded++
		}
	}
	if !value.valid(func(id string) bool { return reported[id] }) {
		return result
	}
	result.sealedJSON, result.sealedText = nil, nil
	for {
		with := result
		with.wire.ModelWrittenChecks = value
		var text, markdown bytes.Buffer
		if _, err := EncodeResult(with); err == nil && RenderResultWithOptions(&text, with, maximalText) == nil && RenderResultMarkdown(&markdown, with, maximalText) == nil || len(value.Kept) == 0 {
			return with
		}
		value = value.clone()
		value.Kept, value.Discarded = value.Kept[:len(value.Kept)-1], value.Discarded+1
	}
}

// modelCheckStatusText says what a kept status means.
var modelCheckStatusText = map[string]string{
	ModelCheckRegression:  "passed twice on base and failed twice on head",
	ModelCheckFailsOnHead: "did not build on base and failed twice on head",
}

// ModelWrittenChecksText words the checks as text lines; finding names the
// finding of a diagnostic identity.
func ModelWrittenChecksText(c *ModelWrittenChecks, finding func(string) string) []string {
	if c == nil {
		return nil
	}
	lines := []string{fmt.Sprintf("model-written checks: %d kept, %d discarded (source: model-written check; they do not change the status or the CI disposition)\n", len(c.Kept), c.Discarded)}
	for _, check := range c.Kept {
		lines = append(lines, fmt.Sprintf("model-written check: %s is demonstrated by %s, which %s; its text is in the JSON result under model_written_checks\n", finding(check.FindingIdentity), check.Path, modelCheckStatusText[check.Status]))
	}
	return lines
}

// ModelWrittenChecksMarkdown renders the checks as a Markdown section.
func ModelWrittenChecksMarkdown(c *ModelWrittenChecks, finding func(string) string) string {
	if c == nil {
		return ""
	}
	var buffer strings.Builder
	buffer.WriteString("### Model-written checks\n\nSource: model-written check. The checker wrote these tests and the sandbox ran each twice on base and on head. They do not change the status or the CI disposition. Their text is in the JSON result under `model_written_checks`.\n\n")
	for _, check := range c.Kept {
		fmt.Fprintf(&buffer, "- %s: %s %s; failing on head: %s\n", MarkdownText(finding(check.FindingIdentity)), MarkdownCode(check.Path), modelCheckStatusText[check.Status], MarkdownCode(strings.Join(check.Tests, ", ")))
	}
	if c.Discarded > 0 {
		fmt.Fprintf(&buffer, "- %d discarded: not valid, not deterministic or no regression shown.\n", c.Discarded)
	}
	return buffer.String()
}

// FindingName names a reported finding by its title and location, for the
// model-written check lines; it is "a finding" when none matches.
func FindingName(findings []ReportFinding) func(string) string {
	return func(identity string) string {
		for _, finding := range findings {
			if finding.Identity == identity {
				return fmt.Sprintf("%q (%s)", finding.Title, SourceText(finding.Path, finding.Side, finding.StartLine, finding.EndLine, finding.HeadLine))
			}
		}
		return "a finding"
	}
}
