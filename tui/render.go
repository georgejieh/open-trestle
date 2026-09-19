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
	builder.WriteString("\nVerified diagnostics (text is untrusted)\n")
	if !view.hasDiagnostics {
		builder.WriteString("No verified diagnostic snapshot is available.\n")
	} else {
		findings := view.diagnostics.Findings()
		fmt.Fprintf(&builder, "%d finding(s), source revision %s\n", len(findings), truncateTerminalText(view.diagnostics.HeadRevision(), 16))
		if view.diagnostics.SchemaVersion() >= 2 {
			fmt.Fprintf(&builder, "%d candidate(s): %d verified\n", view.diagnostics.CandidateCount(), view.diagnostics.VerifiedCount())
			fmt.Fprintf(&builder, "%d rejected, %d inconclusive\n", view.diagnostics.RejectedCount(), view.diagnostics.InconclusiveCount())
			if view.diagnostics.InconclusiveCount() > 0 {
				builder.WriteString("Coverage incomplete: at least one candidate remained inconclusive.\n")
			}
			if view.diagnostics.SchemaVersion() >= 3 {
				fmt.Fprintf(&builder, "%d source(s): %d selected, %d omitted\n", view.diagnostics.SourceAnalyzedCount(), view.diagnostics.SourceSelectedCount(), view.diagnostics.SourceOmittedCount())
				if view.diagnostics.SourceOmittedCount() > 0 {
					builder.WriteString("Source coverage incomplete: at least one analyzed source was omitted.\n")
				}
				if summaries := view.diagnostics.OmissionSummaries(); view.diagnostics.SchemaVersion() >= 4 && len(summaries) > 0 {
					builder.WriteString("Omission reasons:\n")
					for _, summary := range summaries {
						fmt.Fprintf(&builder, "  %d %s\n", summary.Count(), strings.ReplaceAll(summary.Reason().String(), "_", " "))
					}
				}
				if view.diagnostics.SchemaVersion() == 5 {
					check := view.diagnostics.DeterministicChecks()[0]
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
					fmt.Fprintf(&builder, "%d/%d changed Go range(s), %d exact match(es)\n", check.CheckedRanges(), check.ApplicableRanges(), check.MatchCount())
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
			fmt.Fprintf(
				&builder, "%-11s %s  %s\n",
				finding.Severity().String(), location, truncateTerminalText(finding.Title(), available),
			)
		}
	}
	if view.notice != "" {
		fmt.Fprintf(&builder, "\n%s\n", truncateTerminalText(view.notice, width))
	}
	builder.WriteString("\nCommands: r refresh  c cancel  q quit\n")
	_, err := i.output.Write([]byte(builder.String()))
	return err
}
