package localreview

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/patternhygiene"
)

// Rendering of the walkthrough and the ranked findings, shared by the single
// review and the specialist review set, in text and in Markdown for a pull
// request summary comment. Text keeps the historical "finding:" block for each
// finding. Titles, claims, fix text, paths and declaration names are
// untrusted (model output or repository text): Markdown escapes them and never
// lets them open a link, an HTML tag, a heading or a mention.

// RenderOptions selects what text and Markdown output show.
type RenderOptions struct {
	// All lists every confirmed finding. By default only high, critical and
	// medium findings are listed and the rest are counted, unless there are
	// none of those (see FindingSections).
	All bool
	// Verbose adds the internal tokens text output leaves out by default,
	// such as the limitations list and a review set's selection trace and
	// per-member key-value lines. It changes text only; JSON, SARIF and
	// Markdown carry the same fields either way.
	Verbose bool
}

// maximalText is the largest text rendering, which output bounds are checked
// against so that every option fits.
var maximalText = RenderOptions{All: true, Verbose: true}

// maxWalkthroughTextFiles bounds the files the text and Markdown walkthroughs
// list; the JSON result lists up to its own bound.
const maxWalkthroughTextFiles = 32

// HiddenNote is the line that counts findings not shown by default.
func HiddenNote(hidden int) string {
	if hidden == 0 {
		return ""
	}
	return fmt.Sprintf("%d lower-severity finding%s not shown; add --all to list every finding (the JSON output lists all)", hidden, plural(hidden))
}

func plural(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}

// declarationChange words a declaration change.
func declarationChange(change string) string {
	if change == "modified" {
		return "changed"
	}
	return change
}

// scanTotals words a secret scan's totals.
func scanTotals(scan WalkthroughSecretScan) string {
	text := fmt.Sprintf("(%d bytes, %d secret match%s", scan.ScannedBytes, scan.Matches, map[bool]string{true: "", false: "es"}[scan.Matches == 1])
	if scan.RedactedBytes > 0 {
		text += fmt.Sprintf(", %d bytes redacted", scan.RedactedBytes)
	}
	return text + ")"
}

// walkthroughVerifiedTexts are the "what was verified" statements, in order.
// set, when not nil, counts the review set members whose secret scans and
// verifier accounts the totals sum.
func walkthroughVerifiedTexts(w *Walkthrough, code func(string) string, set *setScanCounts) []string {
	verified := w.Verified
	var lines []string
	from := ""
	if set != nil {
		from = fmt.Sprintf(" from %d reviewer%s", set.reviewers-set.scanUnavailable, plural(set.reviewers-set.scanUnavailable))
	}
	switch scan := verified.SecretScan; {
	case scan.State == SecretScanScanned:
		lines = append(lines, fmt.Sprintf("secret scan: %d model request%s%s scanned before sending %s", scan.Requests, plural(scan.Requests), from, scanTotals(scan)))
	case scan.State == SecretScanNotRun:
		lines = append(lines, "secret scan: no model request was prepared")
	case set == nil:
		lines = append(lines, "secret scan: a scan receipt could not be read")
	default:
		text := fmt.Sprintf("secret scan: the scan account of %d of %d reviewers could not be read", set.scanUnavailable, set.reviewers)
		if scan.Requests > 0 {
			text += fmt.Sprintf("; %d model request%s%s scanned before sending %s", scan.Requests, plural(scan.Requests), from, scanTotals(scan))
		}
		lines = append(lines, text)
	}
	for _, check := range verified.StaticChecks {
		lines = append(lines, fmt.Sprintf("static check %s: %s (%d file%s checked, %d match%s)", code(check.Key), check.State, check.CheckedFiles, plural(int(check.CheckedFiles)), check.Matches, map[bool]string{true: "", false: "es"}[check.Matches == 1]))
	}
	lines = append(lines, patternHygieneTexts(verified.PatternHygiene, code)...)
	if verified.StyleDetection.State == "ran" {
		lines = append(lines, fmt.Sprintf("style detection: ran (%d recommendation%s, %d withheld)", verified.StyleDetection.Recommendations, plural(verified.StyleDetection.Recommendations), verified.StyleDetection.Withheld))
	} else {
		lines = append(lines, "style detection: unavailable")
	}
	if impact := verified.SemanticImpact; impact.State == "ran" {
		lines = append(lines, fmt.Sprintf("semantic impact: %d changed declaration%s, %d public API change%s, %d reference%s (%d from tests), %d gap%s", impact.Declarations, plural(impact.Declarations), impact.PublicAPIChanges, plural(impact.PublicAPIChanges), impact.References, plural(impact.References), impact.TestReferences, impact.Gaps, plural(impact.Gaps)))
	} else {
		lines = append(lines, "semantic impact: unavailable (no analysis was recorded)")
	}
	if verifier := verified.Verifier; verifier != nil {
		of := ""
		if set != nil {
			of = fmt.Sprintf(" from %d reviewer%s", set.verified, plural(set.verified))
			if set.verified != set.reviewers {
				of = fmt.Sprintf(" from %d of %d reviewers", set.verified, set.reviewers)
			}
		}
		lines = append(lines, fmt.Sprintf("independent verifier (%s): %d of %d candidate%s%s confirmed, %d rejected, %d inconclusive", verifier.Independence, verifier.Verified, verifier.Candidates, plural(int(verifier.Candidates)), of, verifier.Rejected, verifier.Inconclusive))
	} else {
		lines = append(lines, "independent verifier: no verified set was recorded")
	}
	return lines
}

// patternHygieneTexts words the deterministic pattern-hygiene evidence: one
// summary line, then each listed anti-pattern increase and root-cause note.
func patternHygieneTexts(hygiene *WalkthroughPatternHygiene, code func(string) string) []string {
	if hygiene == nil {
		return nil
	}
	if hygiene.State != "ran" {
		return []string{"pattern hygiene: unavailable (no version 9 generation context was recorded)"}
	}
	text := fmt.Sprintf("pattern hygiene: %d added suppression%s, %d added workaround comment%s, %d spreading anti-pattern%s",
		hygiene.Suppressions, plural(hygiene.Suppressions), hygiene.WorkaroundComments, plural(hygiene.WorkaroundComments), hygiene.SpreadingAntiPatterns, plural(hygiene.SpreadingAntiPatterns))
	if fresh := hygiene.IncreasedAntiPatterns - hygiene.SpreadingAntiPatterns; fresh > 0 {
		text += fmt.Sprintf(", %d new anti-pattern%s", fresh, plural(fresh))
	}
	if hygiene.UnreferencedTODOs > 0 {
		text += fmt.Sprintf(", %d TODO%s without an issue reference", hygiene.UnreferencedTODOs, plural(hygiene.UnreferencedTODOs))
	}
	if hygiene.AbsoluteDirectives > 0 {
		text += fmt.Sprintf(", %d absolute rule%s added to agent instruction files", hygiene.AbsoluteDirectives, plural(hygiene.AbsoluteDirectives))
	}
	if hygiene.UnreadDirectories > 0 {
		text += fmt.Sprintf(" (%d director%s not compared)", hygiene.UnreadDirectories, map[bool]string{true: "y", false: "ies"}[hygiene.UnreadDirectories == 1])
	}
	lines := []string{text}
	for _, item := range hygiene.Items {
		switch patternhygiene.Kind(item.Kind) {
		case patternhygiene.KindAntiPattern:
			what := item.Rule
			if rule, ok := patternhygiene.RuleByID(item.Rule); ok {
				what = rule.Pattern
			}
			spread := "new in its directory"
			if item.BaseCount > 0 {
				spread = fmt.Sprintf("its directory had %d, now %d", item.BaseCount, item.HeadCount)
			}
			lines = append(lines, fmt.Sprintf("pattern hygiene: %s line %d adds %s (%s; %s)", code(item.Path), item.Line, code(item.Rule), what, spread))
		case patternhygiene.KindRootCauseNotFixed:
			lines = append(lines, fmt.Sprintf("pattern hygiene note (deterministic, low): %s line %d adds a suppression beside a workaround comment; the root cause is not fixed", code(item.Path), item.Line))
		}
	}
	return lines
}

// statedIntentText words the author-stated, unverified commit subjects.
func statedIntentText(intent *WalkthroughStatedIntent, quote func(string) string) string {
	parts := make([]string, len(intent.Subjects))
	for index, subject := range intent.Subjects {
		parts[index] = quote(subject)
	}
	text := "stated intent (author-stated, unverified): " + strings.Join(parts, "; ")
	if len(parts) == 0 {
		text = "stated intent (author-stated, unverified): no commit subject could be shown"
	}
	if intent.SubjectsNotListed > 0 {
		text += fmt.Sprintf("; %d more commit%s not listed", intent.SubjectsNotListed, plural(intent.SubjectsNotListed))
	}
	if intent.RangeIncomplete {
		text += "; older commits of the range could not be read"
	}
	if intent.InstructionLike > 0 {
		text += fmt.Sprintf(" (%d flagged as instruction-like text, treated as data)", intent.InstructionLike)
	}
	return text
}

// walkthroughFileText describes one changed file.
func walkthroughFileText(file WalkthroughFile, code func(string) string) string {
	text := code(file.Path) + " " + file.Change
	switch {
	case file.Change == "renamed":
		text += " from " + code(file.RenamedFrom) + " (content unchanged)"
	case file.AddedLines != nil && file.RemovedLines != nil:
		text += fmt.Sprintf(" +%d -%d", *file.AddedLines, *file.RemovedLines)
	default:
		text += " (lines not counted)"
	}
	var parts []string
	for _, declaration := range file.Declarations {
		part := declarationChange(declaration.Change) + " " + declaration.Kind + " " + code(declaration.Name)
		if declaration.PublicAPIChange {
			part += " (public API)"
		}
		parts = append(parts, part)
	}
	if file.DeclarationsNotListed > 0 {
		parts = append(parts, fmt.Sprintf("%d more declaration%s", file.DeclarationsNotListed, plural(file.DeclarationsNotListed)))
	}
	if file.SemanticGap != "" {
		parts = append(parts, "no structural summary ("+file.SemanticGap+")")
	}
	if len(parts) > 0 {
		text += "; " + strings.Join(parts, ", ")
	}
	return text
}

func missingVerificationText(note MissingVerification, code func(string) string) string {
	change := "changed"
	if note.Change == "added" {
		change = "new"
	}
	return fmt.Sprintf("no test file references the %s %s %s (%s)", change, note.Kind, code(note.Name), code(note.Path))
}

func missingIncompleteText() string {
	return "the semantic-impact scan did not read every Go file, so a test it did not read may cover these"
}

// WalkthroughText renders the walkthrough as text lines.
func WalkthroughText(w *Walkthrough) []string {
	if w == nil {
		return nil
	}
	return walkthroughText(w, nil)
}

// SetWalkthroughText renders a review set's walkthrough as text lines: the
// secret scan and verifier lines name how many reviewers they total.
func SetWalkthroughText(w *SetWalkthrough) []string {
	if w == nil {
		return nil
	}
	counts := w.counts()
	return walkthroughText(&w.Walkthrough, &counts)
}

func walkthroughText(w *Walkthrough, set *setScanCounts) []string {
	plain := func(value string) string { return value }
	lines := []string{"walkthrough:\n"}
	for _, text := range walkthroughVerifiedTexts(w, plain, set) {
		lines = append(lines, "verified: "+text+"\n")
	}
	if w.StatedIntent != nil {
		lines = append(lines, statedIntentText(w.StatedIntent, strconv.Quote)+"\n")
	}
	notListed := w.FilesNotListed
	for index, file := range w.Files {
		if index == maxWalkthroughTextFiles {
			notListed += len(w.Files) - index
			break
		}
		lines = append(lines, "file: "+walkthroughFileText(file, plain)+"\n")
	}
	if notListed > 0 {
		lines = append(lines, fmt.Sprintf("file: %d more changed file%s not listed\n", notListed, plural(notListed)))
	}
	for _, note := range w.MissingVerification {
		lines = append(lines, "missing verification: "+missingVerificationText(note, plain)+"\n")
	}
	if w.MissingVerificationNotListed > 0 {
		lines = append(lines, fmt.Sprintf("missing verification: %d more not listed\n", w.MissingVerificationNotListed))
	}
	if w.MissingVerificationIncomplete && (len(w.MissingVerification) > 0 || w.MissingVerificationNotListed > 0) {
		lines = append(lines, "missing verification: "+missingIncompleteText()+"\n")
	}
	return lines
}

// MaxLowerSeverityShown caps the lower-severity findings text and Markdown
// list by default when no confirmed finding is high, critical or medium.
const MaxLowerSeverityShown = 10

// FindingSections splits ranked findings into the shown confirmed findings,
// the shown pre-existing ones and the hidden count. By default it shows the
// high, critical and medium findings and counts the rest; when there is none
// of those, it never hides everything: it shows the first
// MaxLowerSeverityShown lower-severity findings in rank order and counts the
// rest. options.All shows every finding.
func FindingSections(ranked []MergedFinding, options RenderOptions) (confirmed, preExisting []MergedFinding, hidden int) {
	lowerOnly := !slices.ContainsFunc(ranked, MergedFinding.ShownByDefault)
	lowerShown := 0
	for _, group := range ranked {
		switch {
		case options.All || group.ShownByDefault():
		case lowerOnly && lowerShown < MaxLowerSeverityShown:
			lowerShown++
		default:
			hidden++
			continue
		}
		if group.PreExisting() {
			preExisting = append(preExisting, group)
		} else {
			confirmed = append(confirmed, group)
		}
	}
	return confirmed, preExisting, hidden
}

// FindingText renders one ranked finding as its text block. contributors,
// when not nil, adds the review set's "confirmed by" line: the members whose
// verifier confirmed the defect.
func FindingText(group MergedFinding, contributors []string) string {
	finding := group.Finding
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "finding: %s %s\nrank: %d\nsource: %s\nmessage: %s\nevidence: %s\n", finding.Severity.String(), finding.Title, group.Rank, SourceText(finding.Path, finding.Side, finding.StartLine, finding.EndLine, finding.HeadLine), finding.Claim, strings.Join(finding.EvidenceIDs, ", "))
	if finding.Category != "" {
		fmt.Fprintf(&buffer, "category: %s\n", finding.Category)
	}
	if finding.Fix != "" {
		// Fix text is unverified model guidance; it is printed, never applied.
		fmt.Fprintf(&buffer, "fix: %s\n", finding.Fix)
	}
	if contributors != nil {
		fmt.Fprintf(&buffer, "confirmed by: %s\n", strings.Join(contributors, ", "))
	} else if merged := len(group.Contributors) - 1; merged > 0 {
		fmt.Fprintf(&buffer, "merged duplicates: %d\n", merged)
	}
	plain := func(value string) string { return value }
	if also := alsoReportedAs(group, contributors != nil, plain, plain); also != "" {
		fmt.Fprintf(&buffer, "also reported as: %s\n", also)
	}
	return buffer.String()
}

// alsoReportedAs joins the other wordings of a merged defect, each title
// once; withOrigins adds the reviewer that reported each (a review set).
// text renders a title and code an origin label.
func alsoReportedAs(group MergedFinding, withOrigins bool, text, code func(string) string) string {
	parts := []string{}
	for _, contributor := range group.AlsoReportedAs() {
		part := text(contributor.Title)
		if withOrigins {
			part += " (" + code(contributor.Origin) + ")"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "; ")
}

// FindingsText renders the ranked sections: confirmed findings, then
// pre-existing ones, then the hidden count. contributorsOf, when not nil,
// supplies a review set's contributor labels for a finding.
func FindingsText(ranked []MergedFinding, options RenderOptions, contributorsOf func(MergedFinding) []string) string {
	confirmed, preExisting, hidden := FindingSections(ranked, options)
	var buffer bytes.Buffer
	labels := func(group MergedFinding) []string {
		if contributorsOf == nil {
			return nil
		}
		return contributorsOf(group)
	}
	if len(confirmed) > 0 {
		fmt.Fprintf(&buffer, "confirmed findings (ranked): %d\n", len(confirmed))
		for _, group := range confirmed {
			buffer.WriteString(FindingText(group, labels(group)))
		}
	}
	if len(preExisting) > 0 {
		fmt.Fprintf(&buffer, "pre-existing findings (on unchanged lines; they never block CI): %d\n", len(preExisting))
		for _, group := range preExisting {
			buffer.WriteString(FindingText(group, labels(group)))
		}
	}
	if note := HiddenNote(hidden); note != "" {
		buffer.WriteString("hidden: " + note + "\n")
	}
	return buffer.String()
}

// MarkdownText escapes untrusted text for a Markdown paragraph: it can never
// open emphasis, a link, an image, a heading, a table cell, an HTML tag or an
// @-mention, never becomes an autolink, and line breaks become spaces.
func MarkdownText(value string) string {
	value = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(value)
	value = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "@", zeroWidthSpace+"@"+zeroWidthSpace, "\\", "\\\\", "*", "\\*", "_", "\\_", "[", "\\[", "]", "\\]", "(", "\\(", ")", "\\)", "#", "\\#", "!", "\\!", "|", "\\|", "`", "\\`", "~", "\\~").Replace(value)
	return defuseAutolinks(value)
}

const zeroWidthSpace = "​"

// defuseAutolinks breaks every sequence GitHub-flavoured Markdown would turn
// into a link by itself: a scheme such as https:, http:, ftp:, mailto:, xmpp:
// or javascript: (a zero-width space goes before a colon that follows a letter
// or digit and precedes a non-space character), and a www. host (one goes
// before its dot). Email addresses are already broken at their @. The space
// is used rather than an HTML entity because the autolink pass reads text
// after entities are decoded. Only untrusted text goes through this; the
// renderers emit no links of their own.
func defuseAutolinks(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == ':' && index > 0 && isASCIIAlphanumeric(value[index-1]) && index+1 < len(value) && value[index+1] != ' ' {
			builder.WriteString(zeroWidthSpace)
		}
		if character == '.' && index >= 3 && strings.EqualFold(value[index-3:index], "www") && (index == 3 || !isASCIIAlphanumeric(value[index-4])) {
			builder.WriteString(zeroWidthSpace)
		}
		builder.WriteByte(character)
	}
	return builder.String()
}

func isASCIIAlphanumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}

// MarkdownCode renders untrusted text as inline code. Text holding a backtick
// or a line break is escaped as plain text instead, because it could close
// the code span. A pipe is escaped so a table cell stays one cell.
func MarkdownCode(value string) string {
	if value == "" || strings.ContainsAny(value, "`\r\n") {
		return MarkdownText(value)
	}
	return "`" + strings.ReplaceAll(value, "|", "\\|") + "`"
}

// markdownSeverity names a diagnostic severity for people.
func markdownSeverity(severity diagnostics.Severity) string {
	switch severity {
	case diagnostics.SeverityError:
		return "High or critical"
	case diagnostics.SeverityWarning:
		return "Medium"
	case diagnostics.SeverityInformation:
		return "Low"
	}
	return "Hint"
}

// WalkthroughMarkdown renders the walkthrough's Markdown sections.
func WalkthroughMarkdown(w *Walkthrough) string {
	if w == nil {
		return ""
	}
	return walkthroughMarkdown(w, nil)
}

// SetWalkthroughMarkdown renders a review set's walkthrough's Markdown
// sections, with the totals over its reviewers.
func SetWalkthroughMarkdown(w *SetWalkthrough) string {
	if w == nil {
		return ""
	}
	counts := w.counts()
	return walkthroughMarkdown(&w.Walkthrough, &counts)
}

func walkthroughMarkdown(w *Walkthrough, set *setScanCounts) string {
	var buffer bytes.Buffer
	buffer.WriteString("### What was verified\n\n")
	for _, text := range walkthroughVerifiedTexts(w, MarkdownCode, set) {
		buffer.WriteString("- " + strings.ToUpper(text[:1]) + text[1:] + ".\n")
	}
	if intent := w.StatedIntent; intent != nil {
		buffer.WriteString("\n### Stated intent\n\nAuthor-stated and unverified: what the commit messages say the change does, not evidence.\n\n")
		for _, subject := range intent.Subjects {
			buffer.WriteString("- " + MarkdownCode(subject) + "\n")
		}
		if intent.SubjectsNotListed > 0 {
			fmt.Fprintf(&buffer, "- %d more commit%s, not listed.\n", intent.SubjectsNotListed, plural(intent.SubjectsNotListed))
		}
		if intent.RangeIncomplete {
			buffer.WriteString("- Older commits of the range could not be read.\n")
		}
		if intent.InstructionLike > 0 {
			fmt.Fprintf(&buffer, "- %d flagged as instruction-like text and treated as data.\n", intent.InstructionLike)
		}
	}
	if len(w.Files) > 0 || w.FilesNotListed > 0 {
		buffer.WriteString("\n### Changes\n\n")
		notListed := w.FilesNotListed
		for index, file := range w.Files {
			if index == maxWalkthroughTextFiles {
				notListed += len(w.Files) - index
				break
			}
			buffer.WriteString("- " + walkthroughFileText(file, MarkdownCode) + "\n")
		}
		if notListed > 0 {
			fmt.Fprintf(&buffer, "- %d more changed file%s, listed in the JSON output.\n", notListed, plural(notListed))
		}
	}
	if len(w.MissingVerification) > 0 || w.MissingVerificationNotListed > 0 {
		buffer.WriteString("\n### Missing verification\n\nInformational, not a defect.\n\n")
		for _, note := range w.MissingVerification {
			text := missingVerificationText(note, MarkdownCode)
			buffer.WriteString("- " + strings.ToUpper(text[:1]) + text[1:] + ".\n")
		}
		if w.MissingVerificationNotListed > 0 {
			fmt.Fprintf(&buffer, "- %d more, listed in the JSON output.\n", w.MissingVerificationNotListed)
		}
		if w.MissingVerificationIncomplete {
			buffer.WriteString("- Note: " + missingIncompleteText() + ".\n")
		}
	}
	return buffer.String()
}

// findingMarkdown renders one ranked finding as a Markdown list item.
func findingMarkdown(group MergedFinding, contributors []string) string {
	finding := group.Finding
	location := MarkdownCode(fmt.Sprintf("%s:%d-%d", finding.Path, finding.StartLine, finding.EndLine))
	if finding.Side == diagnostics.LineSideBase {
		location = MarkdownCode(finding.Path) + fmt.Sprintf(" removed base lines %d-%d", finding.StartLine, finding.EndLine)
	}
	var buffer bytes.Buffer
	fmt.Fprintf(&buffer, "%d. **%s: %s** (%s", group.Rank, markdownSeverity(finding.Severity), MarkdownText(finding.Title), location)
	if finding.Category != "" {
		buffer.WriteString(", " + MarkdownText(finding.Category))
	}
	buffer.WriteString(")\n")
	fmt.Fprintf(&buffer, "   %s\n", MarkdownText(finding.Claim))
	if finding.Fix != "" {
		fmt.Fprintf(&buffer, "   Fix (unverified model guidance): %s\n", MarkdownText(finding.Fix))
	}
	if len(contributors) > 0 {
		escaped := make([]string, 0, len(contributors))
		for _, label := range contributors {
			escaped = append(escaped, MarkdownCode(label))
		}
		fmt.Fprintf(&buffer, "   Confirmed by: %s\n", strings.Join(escaped, ", "))
	} else if merged := len(group.Contributors) - 1; merged > 0 && contributors == nil {
		fmt.Fprintf(&buffer, "   Merged duplicates: %d\n", merged)
	}
	if also := alsoReportedAs(group, len(contributors) > 0, MarkdownText, MarkdownCode); also != "" {
		fmt.Fprintf(&buffer, "   Also reported as: %s\n", also)
	}
	return buffer.String()
}

// FindingsMarkdown renders the ranked Markdown sections.
func FindingsMarkdown(ranked []MergedFinding, options RenderOptions, contributorsOf func(MergedFinding) []string) string {
	confirmed, preExisting, hidden := FindingSections(ranked, options)
	labels := func(group MergedFinding) []string {
		if contributorsOf == nil {
			return nil
		}
		return contributorsOf(group)
	}
	var buffer bytes.Buffer
	buffer.WriteString("\n### Confirmed findings\n\n")
	if len(confirmed) == 0 {
		buffer.WriteString("None listed.\n")
	}
	for _, group := range confirmed {
		buffer.WriteString(findingMarkdown(group, labels(group)))
	}
	if len(preExisting) > 0 {
		buffer.WriteString("\n### Pre-existing findings\n\nOn unchanged lines the change did not touch; they never block CI.\n\n")
		for _, group := range preExisting {
			buffer.WriteString(findingMarkdown(group, labels(group)))
		}
	}
	if note := HiddenNote(hidden); note != "" {
		buffer.WriteString("\n_" + strings.ToUpper(note[:1]) + MarkdownText(note[1:]) + "._\n")
	}
	return buffer.String()
}

// MarkdownFooter is the closing note of every Markdown summary.
const MarkdownFooter = "\n<sub>Open Trestle. Comprehensive clearance: false. Each finding was proposed by the finder model and confirmed by an independent checker; titles, claims and fix text are untrusted model output, and nothing applies the fix text.</sub>\n"

// RenderResultMarkdown writes a result as Markdown for a pull request summary
// comment: the status, the walkthrough, then the ranked sections.
func RenderResultMarkdown(writer io.Writer, r Result, options RenderOptions) error {
	if nilValue(writer) || !r.valid {
		return ErrInvalidResult
	}
	report, err := r.Report()
	if err != nil {
		return err
	}
	var buffer bytes.Buffer
	buffer.WriteString("## Open Trestle review\n\n")
	fmt.Fprintf(&buffer, "**Status:** %s · **CI:** %s · **Run:** %s\n", MarkdownText(report.Status), MarkdownText(report.CIDisposition), MarkdownText(report.RunStatus))
	if class, task, detail, hint := r.failureSummary(); class != "" {
		fmt.Fprintf(&buffer, "\n**Failure:** %s\n", MarkdownText(FailureLine(class, task, detail)))
		if hint != "" {
			fmt.Fprintf(&buffer, "\n%s\n", MarkdownText(hint))
		}
	}
	if report.SpecialistProfileID != "" {
		fmt.Fprintf(&buffer, "\nSpecialist profile: %s\n", MarkdownCode(report.SpecialistProfileID))
	}
	if report.Walkthrough != nil {
		buffer.WriteString("\n" + WalkthroughMarkdown(report.Walkthrough))
	}
	if len(report.Ranked) > 0 || report.Status == "findings" {
		buffer.WriteString(FindingsMarkdown(report.Ranked, options, nil))
	}
	buffer.WriteString(MarkdownFooter)
	if buffer.Len() > MaxResultTextBytes {
		return ErrInvalidResult
	}
	n, err := writer.Write(buffer.Bytes())
	if err == nil && n != buffer.Len() {
		err = io.ErrShortWrite
	}
	return err
}
