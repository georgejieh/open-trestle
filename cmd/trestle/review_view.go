package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/localreview"
)

// reviewView is a finished review as a person reads it on a terminal: the
// verdict, the findings, then what was checked. It is built from a single
// result or a review set and holds no source, prompt or model reply beyond
// the findings' own text. `trestle review --verbose` and every output that
// is not a terminal keep the full text document instead.
type reviewView struct {
	status, ci, failure, hint string
	// reviewers ran out of selected in a review set; selected is 0 for a
	// single review.
	reviewers   []string
	selected    int
	unfinished  []reviewViewMember
	regressions *localreview.CheckRegressions
	// modelChecks are the checker's kept tests, shown under their findings.
	modelChecks *localreview.ModelWrittenChecks
	finished    bool
	walkthrough *localreview.Walkthrough
	ranked      []localreview.MergedFinding
	set         bool
	omitted     uint32
	zdrOff      bool
}

// reviewViewMember is a reviewer of a set that did not finish or did not run.
type reviewViewMember struct {
	launched           bool
	member, text, hint string
}

func singleReviewView(report localreview.Report) *reviewView {
	view := &reviewView{status: report.Status, ci: report.CIDisposition, regressions: report.CheckRegressions, modelChecks: report.ModelWrittenChecks, finished: report.RunStatus == "succeeded", walkthrough: report.Walkthrough, ranked: report.Ranked}
	if !view.finished && report.Failure != "" {
		view.failure, view.hint = localreview.FailureLine(report.Failure, report.FailureTask, report.FailureDetail), report.FailureHint
	}
	if report.HasSourceCoverage {
		view.omitted = report.SourceOmitted
	}
	view.zdrOff = slices.Contains(report.Limitations, localreview.LimitationOpenRouterZDRNotRequired)
	return view
}

func setReviewView(set modelReviewSetWire) *reviewView {
	view := &reviewView{status: set.Status, ci: set.CI, selected: set.Summary.MembersSelected, regressions: set.CheckRegressions, modelChecks: set.ModelWrittenChecks, finished: set.Complete, ranked: set.rankedGroups(), set: true}
	if set.Walkthrough != nil {
		view.walkthrough = &set.Walkthrough.Walkthrough
	}
	for _, member := range set.Members {
		view.zdrOff = view.zdrOff || slices.Contains(member.Limitations, localreview.LimitationOpenRouterZDRNotRequired)
		switch {
		case !member.Launched:
			view.unfinished = append(view.unfinished, reviewViewMember{member: member.Member, text: notLaunchedText(member.NotLaunchedReason)})
			continue
		case member.RunStatus != "succeeded":
			text := member.Status
			if member.Failure != "" {
				text += ": " + localreview.FailureLine(member.Failure, member.FailureTask, member.FailureDetail)
			}
			view.unfinished = append(view.unfinished, reviewViewMember{launched: true, member: member.Member, text: text, hint: member.failureHint})
		}
		view.reviewers = append(view.reviewers, member.Member)
	}
	if coverage := set.Summary.SourceCoverage; coverage != nil {
		view.omitted = coverage.Omitted
	}
	return view
}

// reviewViewText makes model and repository text safe for a terminal.
func reviewViewText(text string) string { return terminalText(text, 2000) }

// render prints the view; code is the command's exit status.
func (v *reviewView) render(p outPrinter, code int, options localreview.RenderOptions) {
	p.sayVerbatim("")
	p.rows(v.verdict(p, code))
	if v.selected > 0 {
		p.detail(fmt.Sprintf("%d of %d reviewers ran: %s", len(v.reviewers), v.selected, joinOrNone(v.reviewers)), initToneDim)
	}
	if v.failure != "" {
		p.detail("Failure: "+v.failure, initToneBody)
		if v.hint != "" {
			p.detail(v.hint, initToneDim)
		}
	}
	for _, member := range v.unfinished {
		mark, what := p.optional, "did not run"
		if member.launched {
			mark, what = p.wait, "did not finish"
		}
		p.rows(outRow{mark: mark, value: member.member + " " + what + ": " + member.text})
		if member.hint != "" {
			p.detail(member.hint, initToneDim)
		}
	}
	if v.set && !v.finished && len(v.ranked) > 0 {
		p.detail("The findings come only from the reviewers that finished, so this is not a clean result.", initToneBody)
	}
	v.renderRegressions(p)
	confirmed, preExisting, hidden := localreview.FindingSections(v.ranked, options)
	for _, group := range confirmed {
		v.renderFinding(p, group)
	}
	if len(preExisting) > 0 {
		p.sayVerbatim("")
		p.heading("  Pre-existing (on unchanged lines; they never block CI)")
		for _, group := range preExisting {
			v.renderFinding(p, group)
		}
	}
	if note := localreview.HiddenNote(hidden); note != "" {
		p.sayVerbatim("")
		p.aside(strings.ToUpper(note[:1]) + note[1:] + ".")
	}
	p.sayVerbatim("")
	if checked := v.checked(); len(checked) > 0 {
		p.say("%s", "  Checked:  "+strings.Join(checked, " · "))
	}
	if v.zdrOff {
		p.say("  %s Zero data retention was not required on an OpenRouter route this review used.", p.wait)
	}
	p.hint("  Not a complete audit. Details: trestle review --verbose")
}

// verdict is the first line: what the review found and its exit status.
func (v *reviewView) verdict(p outPrinter, code int) outRow {
	row := outRow{mark: p.bad}
	findings := fmt.Sprintf("%d confirmed finding%s", len(v.ranked), initPlural(len(v.ranked)))
	switch {
	case v.status == "findings" && v.ci == "inconclusive":
		row.mark, row.value = p.wait, findings+", none blocking"
	case v.status == "findings":
		row.value = findings
	case v.status == "no_candidates" && v.regressions != nil:
		row.value = "No model finding, but check regressions"
	case v.status == "no_candidates":
		row.mark, row.value = p.ok, "No problem found and confirmed"
	case v.status == "incomplete":
		row.mark, row.value = p.wait, "The review could not cover everything"
	case v.status == "canceled":
		row.mark, row.value = p.wait, "The review was stopped before it finished"
	case v.status == "refused":
		row.value = "The review was refused"
	default:
		row.value = "The review did not finish (" + v.status + ")"
	}
	row.value += fmt.Sprintf(" · CI %s (exit %d)", v.ci, code)
	return row
}

func (v *reviewView) renderRegressions(p outPrinter) {
	c := v.regressions
	if c == nil {
		return
	}
	p.sayVerbatim("")
	p.rows(outRow{mark: p.bad, value: fmt.Sprintf("%d check regression%s: test%s that passed on base fail on head", c.Count, initPlural(c.Count), initPlural(c.Count))})
	p.detail("From the repository's own checks, not a model finding.", initToneDim)
	for _, test := range c.Tests {
		p.detail(reviewViewText(test.Check+": "+test.Test), initToneBody)
	}
	if c.NotListed > 0 {
		p.detail(fmt.Sprintf("%d more not listed", c.NotListed), initToneDim)
	}
	if !v.finished {
		p.detail("The model review did not finish; these come from the repository's own tests alone.", initToneBody)
	}
}

// reviewSeverityTones colors a severity: danger for high and critical
// (error), the warning tone for medium, dim for the rest.
var reviewSeverityTones = map[diagnostics.Severity]initTone{diagnostics.SeverityError: initToneDanger, diagnostics.SeverityWarning: initToneWarning}

func (v *reviewView) renderFinding(p outPrinter, group localreview.MergedFinding) {
	finding := group.Finding
	number := fmt.Sprintf("  %d. ", group.Rank)
	hang := strings.Repeat(" ", len(number))
	tone, ok := reviewSeverityTones[finding.Severity]
	if !ok {
		tone = initToneDim
	}
	severity := finding.Severity.String()
	p.sayVerbatim("")
	for i, part := range initFit(hang+severity+"  "+reviewViewText(finding.Title), initWidth) {
		if i == 0 {
			part = number + p.style.paint(tone, severity) + strings.TrimPrefix(part, hang+severity)
		}
		p.sayVerbatim(part)
	}
	where := []string{reviewViewText(localreview.SourceText(finding.Path, finding.Side, finding.StartLine, finding.EndLine, finding.HeadLine))}
	if finding.Category != "" {
		where = append(where, reviewViewText(finding.Category))
	}
	if v.set {
		where = append(where, "confirmed by "+reviewViewText(strings.Join(group.OriginLabels(), ", ")))
	}
	say := func(text string, tone initTone) {
		for _, part := range initFit(hang+text, initWidth) {
			p.sayVerbatim(p.style.paint(tone, part))
		}
	}
	say(strings.Join(where, " · "), initToneDim)
	say(reviewViewText(finding.Claim), initToneBody)
	if finding.Fix != "" {
		say("Fix: "+reviewViewText(finding.Fix), initToneBody)
	}
	if v.modelChecks != nil {
		for _, check := range v.modelChecks.Kept {
			named := func(contributor localreview.FindingContributor) bool {
				return contributor.Identity == check.FindingIdentity
			}
			if finding.Identity == check.FindingIdentity || slices.ContainsFunc(group.Contributors, named) {
				say("Test: "+reviewViewText(check.Path)+" shows it ("+modelCheckViewText[check.Status]+"; written by the checker, so it does not change CI)", initToneBody)
			}
		}
	}
	if group.UnprovenOrigin() {
		say("Origin: unproven: on unchanged lines the change may affect, so it blocks like a new finding.", initToneDim)
	}
	also := []string{}
	for _, contributor := range group.AlsoReportedAs() {
		also = append(also, reviewViewText(contributor.Title))
	}
	if len(also) > 0 {
		say("Also reported as: "+strings.Join(also, "; "), initToneDim)
	}
}

// checked is the short account of what was verified.
func (v *reviewView) checked() []string {
	parts := []string{}
	if v.walkthrough != nil {
		verified := v.walkthrough.Verified
		switch scan := verified.SecretScan; {
		case scan.State == localreview.SecretScanScanned && scan.Matches == 0:
			parts = append(parts, "secret scan clean")
		case scan.State == localreview.SecretScanScanned:
			parts = append(parts, fmt.Sprintf("secret scan redacted %d match%s", scan.Matches, map[bool]string{true: "", false: "es"}[scan.Matches == 1]))
		case scan.State != localreview.SecretScanNotRun:
			parts = append(parts, "a secret scan receipt could not be read")
		}
		if verifier := verified.Verifier; verifier != nil {
			parts = append(parts, fmt.Sprintf("checker confirmed %d of %d candidate%s", verifier.Verified, verifier.Candidates, initPlural(int(verifier.Candidates))))
		}
		if untested := len(v.walkthrough.MissingVerification) + v.walkthrough.MissingVerificationNotListed; untested > 0 {
			parts = append(parts, fmt.Sprintf("%d changed function%s without a test", untested, initPlural(untested)))
		}
	}
	if v.omitted > 0 {
		parts = append(parts, fmt.Sprintf("%d source item%s left out", v.omitted, initPlural(int(v.omitted))))
	}
	return parts
}

// modelCheckViewText says briefly what a kept model-written check showed.
var modelCheckViewText = map[string]string{
	localreview.ModelCheckRegression:  "passes on base, fails on head",
	localreview.ModelCheckFailsOnHead: "fails on head, does not build on base",
}
