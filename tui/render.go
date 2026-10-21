package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/diagnostics"
)

func (i *Interface) render(view interfaceView) error {
	var builder strings.Builder
	if !i.options.Plain {
		builder.WriteString("\x1b[H\x1b[2J")
	} else {
		builder.WriteString("---\n")
	}
	width := i.options.Width
	builder.WriteString("OPEN TRESTLE\n")
	writeAmbassadorBridgeMark(&builder)
	scope := view.receipt.Scope()
	scopeText := fmt.Sprintf("%s / %s / %s", scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID())
	fmt.Fprintf(&builder, "Scope       %s\n", truncateTerminalText(scopeText, width-12))
	fmt.Fprintf(&builder, "Run         %-12s revision %d\n", view.receipt.Status().String(), view.receipt.Revision())
	fmt.Fprintf(&builder, "Updated     %s\n", view.refreshedAt.Format("2006-01-02 15:04:05 UTC"))
	if failure := view.receipt.Failure().String(); failure != "" {
		fmt.Fprintf(&builder, "Disposition %s\n", failure)
	}
	builder.WriteString("\nTasks\n")
	keyWidth := (width - 23) / 2
	kindWidth := width - 23 - keyWidth
	fmt.Fprintf(&builder, "%-*s %-*s %-12s %8s\n", keyWidth, "KEY", kindWidth, "KIND", "STATUS", "ATTEMPTS")
	for _, task := range view.receipt.Tasks() {
		attempts := fmt.Sprintf("%d/%d", task.Attempts(), task.MaxAttempts())
		fmt.Fprintf(
			&builder, "%-*s %-*s %-12s %8s\n",
			keyWidth, truncateTerminalText(task.Key(), keyWidth),
			kindWidth, truncateTerminalText(task.Kind().String(), kindWidth),
			task.Status().String(), attempts,
		)
	}
	builder.WriteString("\nReview diagnostics (text is untrusted)\n")
	if !view.hasDiagnostics {
		builder.WriteString("No diagnostic snapshot is available.\n")
	} else if view.diagnostics.SchemaVersion() == 7 {
		writeFinalDiagnostics(&builder, view.diagnostics, width)
	} else if view.diagnostics.SchemaVersion() == 6 {
		writeDeterministicDiagnostics(&builder, view.diagnostics, width)
	} else {
		writeVerifiedDiagnostics(&builder, view.diagnostics, width)
	}
	if view.notice != "" {
		fmt.Fprintf(&builder, "\n%s\n", truncateTerminalText(view.notice, width))
	}
	builder.WriteString("\nCommands: r refresh  c cancel  q quit\n")
	_, err := i.output.Write([]byte(builder.String()))
	return err
}

func writeFinalDiagnostics(builder *strings.Builder, set diagnostics.Set, width int) {
	fmt.Fprintf(builder, "Final review outcome: %s\n", set.Outcome())
	builder.WriteString("A terminal outcome does not approve the change or prove correctness.\n")
	if set.AnalysisResultIdentity() == "" {
		builder.WriteString("Deterministic observations: unknown (evidence unavailable).\n")
	} else {
		builder.WriteString("\nDeterministic observations (not independently verified)\n")
		writeDeterministicDiagnostics(builder, set, width)
	}
	if set.VerifiedSetIdentity() == "" {
		builder.WriteString("Verified findings: unknown (evidence unavailable).\n")
	} else {
		builder.WriteString("\nVerified findings\n")
		writeVerifiedDiagnostics(builder, set, width)
	}
}

func writeDeterministicDiagnostics(builder *strings.Builder, set diagnostics.Set, width int) {
	observations := set.DeterministicObservations()
	check := set.DeterministicChecks()[0]
	fmt.Fprintf(builder, "%d deterministic observation(s), source revision %s\n", len(observations), truncateTerminalText(set.HeadRevision(), 16))
	switch check.State() {
	case diagnostics.CheckPassed:
		builder.WriteString("Cleared gate: static debug output passed for this exact rule only.\n")
	case diagnostics.CheckFailed:
		builder.WriteString("Failed check: static debug output failed; exact matches require review.\n")
	case diagnostics.CheckIncomplete:
		builder.WriteString("Incomplete check: static debug output did not cover every applicable range.\n")
	case diagnostics.CheckNotApplicable:
		builder.WriteString("Abstention: no changed Go range was applicable; this rule was not cleared.\n")
	}
	fmt.Fprintf(builder, "%d/%d changed Go range(s), %d exact match(es)\n", check.CheckedRanges(), check.ApplicableRanges(), check.MatchCount())
	builder.WriteString("Deterministic observations are not independently verified findings and do not approve the change.\n")
	for _, observation := range observations {
		location := fmt.Sprintf("%s:%d", safeTerminalText(observation.Path()), observation.StartLine())
		if observation.EndLine() != observation.StartLine() {
			location += fmt.Sprintf("-%d", observation.EndLine())
		}
		location = truncateTerminalText(location, width/2)
		available := width - 14 - utf8.RuneCountInString(location)
		if available < 1 {
			available = 1
		}
		fmt.Fprintf(builder, "%-11s %s  %s\n", observation.Severity().String(), location, truncateTerminalText(observation.Title(), available))
	}
}

func writeVerifiedDiagnostics(builder *strings.Builder, set diagnostics.Set, width int) {
	findings := set.Findings()
	fmt.Fprintf(builder, "%d verified finding(s), source revision %s\n", len(findings), truncateTerminalText(set.HeadRevision(), 16))
	if set.SchemaVersion() >= 2 {
		fmt.Fprintf(builder, "%d candidate(s): %d verified\n", set.CandidateCount(), set.VerifiedCount())
		fmt.Fprintf(builder, "%d rejected, %d inconclusive\n", set.RejectedCount(), set.InconclusiveCount())
		if set.InconclusiveCount() > 0 {
			builder.WriteString("Coverage incomplete: at least one candidate remained inconclusive.\n")
		}
		if set.SchemaVersion() >= 3 {
			fmt.Fprintf(builder, "%d source(s): %d selected, %d omitted\n", set.SourceAnalyzedCount(), set.SourceSelectedCount(), set.SourceOmittedCount())
			if set.SourceOmittedCount() > 0 {
				builder.WriteString("Source coverage incomplete: at least one analyzed source was omitted.\n")
			}
			if summaries := set.OmissionSummaries(); set.SchemaVersion() >= 4 && len(summaries) > 0 {
				builder.WriteString("Omission reasons:\n")
				for _, summary := range summaries {
					fmt.Fprintf(builder, "  %d %s\n", summary.Count(), strings.ReplaceAll(summary.Reason().String(), "_", " "))
				}
			}
			if set.SchemaVersion() == 5 {
				check := set.DeterministicChecks()[0]
				switch check.State() {
				case diagnostics.CheckPassed:
					builder.WriteString("Cleared gate: static debug output passed.\n")
				case diagnostics.CheckFailed:
					builder.WriteString("Failed check: static debug output failed; exact matches require review.\n")
				case diagnostics.CheckIncomplete:
					builder.WriteString("Incomplete check: static debug output did not cover every applicable range; human review is required.\n")
				case diagnostics.CheckNotApplicable:
					builder.WriteString("Abstention: no changed Go range was applicable; this rule was not cleared.\n")
				}
				fmt.Fprintf(builder, "%d/%d changed Go range(s), %d exact match(es)\n", check.CheckedRanges(), check.ApplicableRanges(), check.MatchCount())
			}
		}
		builder.WriteString("Coverage does not approve the change or prove correctness.\n")
	}
	for _, finding := range findings {
		location := fmt.Sprintf("%s:%d", safeTerminalText(finding.Path()), finding.StartLine())
		if finding.EndLine() != finding.StartLine() {
			location += fmt.Sprintf("-%d", finding.EndLine())
		}
		location = truncateTerminalText(location, width/2)
		available := width - 14 - utf8.RuneCountInString(location)
		if available < 1 {
			available = 1
		}
		fmt.Fprintf(builder, "%-11s %s  %s\n", finding.Severity().String(), location, truncateTerminalText(finding.Title(), available))
	}
}
