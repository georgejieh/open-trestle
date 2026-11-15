package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/localreview"
)

func runModelReviewOutput(t *testing.T, f *localModelFixture, extra []string, wantCode int) string {
	t.Helper()
	args := append([]string(nil), f.args...)
	for index := 0; index < len(extra); index++ {
		if extra[index] == "--format" {
			args = replaceLocalGitChangeValue(args, "--format", extra[index+1])
			index++
			continue
		}
		args = append(args, extra[index])
	}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != wantCode || stderr.Len() != 0 {
		t.Fatalf("exit=%d want=%d stderr=%q stdout=%s", code, wantCode, stderr.String(), stdout.String())
	}
	for _, forbidden := range []string{localModelSecret, localModelKey, "return 10 / x", f.objects, f.policyPath} {
		if strings.Contains(stdout.String(), forbidden) {
			t.Fatal("output disclosed private source, configuration or credentials")
		}
	}
	return stdout.String()
}

// requireInOrder fails unless every want appears in text, each after the last.
func requireInOrder(t *testing.T, text string, wants ...string) {
	t.Helper()
	position := 0
	for _, want := range wants {
		index := strings.Index(text[position:], want)
		if index < 0 {
			t.Fatalf("output lacks %q after position %d:\n%s", want, position, text)
		}
		position += index + len(want)
	}
}

// Text output leads with the walkthrough, then the ranked confirmed findings,
// then coverage and limitations.
func TestModelReviewTextShowsWalkthroughThenRankedFindings(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true})
	text := runModelReviewOutput(t, f, []string{"--format", "text"}, 4)
	requireInOrder(t, text,
		"status: findings\n", "ci: blocked\n",
		"walkthrough:\n",
		"verified: secret scan: 2 model requests scanned before sending (",
		"verified: static check static_debug_output: passed (1 file checked, 0 matches)\n",
		"verified: style detection: ran (1 recommendation, 0 withheld)\n",
		"verified: semantic impact: 1 changed declaration, 0 public API changes, 1 reference (0 from tests), 0 gaps\n",
		"verified: independent verifier (distinct_provider): 1 of 1 candidate confirmed, 0 rejected, 0 inconclusive\n",
		"file: a.go modified +1 -1; changed function Changed\n",
		"missing verification: no test file references the changed function Changed (a.go)\n",
		"confirmed findings (ranked): 1\n",
		"finding: error Zero-valued caller now panics\nrank: 1\nsource: a.go:2-2\n",
		"coverage: candidates=1 verified=1 rejected=0 inconclusive=0\n",
		"limitations: ", "comprehensive clearance: false\n")
	if strings.Contains(text, "hidden:") || strings.Contains(text, "pre-existing findings") {
		t.Fatalf("text shows sections it has no findings for:\n%s", text)
	}
}

// A low-severity finding is listed when no confirmed finding outranks it:
// text, Markdown and a review set never hide every finding. JSON carries it
// either way, with its rank.
func TestModelReviewListsLowSeverityWhenNothingOutranksIt(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true, verificationMode: "low"})
	text := runModelReviewOutput(t, f, []string{"--format", "text"}, 4)
	requireInOrder(t, text, "walkthrough:\n", "confirmed findings (ranked): 1\n", "finding: information Zero-valued caller now panics\nrank: 1\n")
	if strings.Contains(text, "hidden:") {
		t.Fatalf("default text hid the only finding:\n%s", text)
	}
	markdown := runModelReviewOutput(t, f, []string{"--format", "markdown"}, 4)
	requireInOrder(t, markdown, "### Confirmed findings\n\n1. **Low: Zero-valued caller now panics**")
	if strings.Contains(markdown, "None listed.") || strings.Contains(markdown, "not shown") {
		t.Fatalf("default Markdown hid the only finding:\n%s", markdown)
	}
	set := runModelReviewOutput(t, f, []string{"--specialists", "bug_hunter", "--format", "text"}, 4)
	requireInOrder(t, set, "confirmed findings (ranked): 1\n", "finding: information Zero-valued caller now panics\n")
	if strings.Contains(set, "hidden:") {
		t.Fatalf("default set text hid the only finding:\n%s", set)
	}
	all := runModelReviewOutput(t, f, []string{"--format", "text", "--all"}, 4)
	requireInOrder(t, all, "confirmed findings (ranked): 1\n", "finding: information Zero-valued caller now panics\nrank: 1\n")
	var receipt judgementReceipt
	if err := json.Unmarshal([]byte(runModelReviewOutput(t, f, nil, 4)), &receipt); err != nil || len(receipt.Rank) != 1 || len(receipt.Diagnostics.Findings) != 1 {
		t.Fatalf("JSON lost the low finding or its rank: %+v %v", receipt, err)
	}
	// --all is a bare flag and may be given once.
	var stdout, stderr bytes.Buffer
	if code := run(append(append([]string(nil), f.args...), "--all", "--all"), &stdout, &stderr); code != 2 {
		t.Fatalf("a repeated --all was accepted: exit %d", code)
	}
}

// A pre-existing finding gets its own text section after the confirmed ones.
func TestModelReviewTextListsPreExistingSection(t *testing.T) {
	f := oldFunctionFixture(t, "pre_existing")
	text := runModelReviewOutput(t, f, []string{"--format", "text"}, 3)
	requireInOrder(t, text, "status: findings\n", "ci: inconclusive\n", "walkthrough:\n", "pre-existing findings (on unchanged lines; they never block CI): 1\n", "finding: error Consume always passes a literal zero\nrank: 1\nsource: caller.go:2-2\n")
	if strings.Contains(text, "confirmed findings (ranked)") {
		t.Fatalf("a pre-existing finding was listed as introduced:\n%s", text)
	}
}

// --format markdown is a pull request summary: status, what was verified,
// changes, missing verification, then the ranked findings and the footer.
func TestModelReviewMarkdownRenderer(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true})
	markdown := runModelReviewOutput(t, f, []string{"--format", "markdown"}, 4)
	requireInOrder(t, markdown,
		"## Open Trestle review\n\n**Status:** findings · **CI:** blocked · **Run:** succeeded\n",
		"### What was verified\n\n- Secret scan: 2 model requests scanned before sending (",
		"- Static check `static_debug_output`: passed (1 file checked, 0 matches).\n",
		"- Independent verifier (distinct_provider): 1 of 1 candidate confirmed, 0 rejected, 0 inconclusive.\n",
		"### Changes\n\n- `a.go` modified +1 -1; changed function `Changed`\n",
		"### Missing verification\n\nInformational, not a defect.\n\n- No test file references the changed function `Changed` (`a.go`).\n",
		"### Confirmed findings\n\n1. **High or critical: Zero-valued caller now panics** (`a.go:2-2`, correctness)\n   Consume passes zero to Changed after removal of the division guard.\n   Fix (unverified model guidance): Restore the zero guard before dividing.\n",
		"<sub>Open Trestle. Comprehensive clearance: false.")
	set := runModelReviewOutput(t, f, []string{"--specialists", "bug_hunter", "--format", "markdown"}, 4)
	requireInOrder(t, set, "## Open Trestle review\n\n**Status:** findings · **CI:** blocked · **Complete:** true\n", "Reviewers: `general`, `bug_hunter` (2 of 2 ran; specialists explicit).\n", "### What was verified\n", "### Confirmed findings\n\n1. **High or critical: Zero-valued caller now panics**", "   Confirmed by: `general`, `bug_hunter`\n", "<sub>Open Trestle.")
}

// Markdown escapes untrusted model and repository text: no HTML, link,
// image, heading, table cell, mention or code-span break survives.
func TestMarkdownEscapesUntrustedText(t *testing.T) {
	hostile := "<img src=x onerror=alert(1)> @team [click](https://evil.test) ![i](x) # head | cell `code`\nnext"
	escaped := localreview.MarkdownText(hostile)
	for _, forbidden := range []string{"<img", "@team", "[click]", "](", "![", "\n", "`code`"} {
		if strings.Contains(escaped, forbidden) {
			t.Fatalf("MarkdownText left %q in %q", forbidden, escaped)
		}
	}
	if strings.Contains(strings.ReplaceAll(escaped, "\\|", ""), "|") || strings.Contains(strings.ReplaceAll(escaped, "\\#", ""), "#") {
		t.Fatalf("MarkdownText left an unescaped table or heading mark in %q", escaped)
	}
	// GitHub-flavoured Markdown autolinks bare URLs, www. hosts and email
	// addresses; none may survive in untrusted text.
	for _, value := range []string{
		"see https://evil.example/x now", "http://evil.example", "ftp://evil.example/f", "HTTPS://EVIL.EXAMPLE",
		"www.evil.example/path", "WWW.Evil.example", "mailto:admin@evil.example", "mailto:nobody", "write to admin@evil.example today",
		"xmpp:user@evil.example", "javascript:alert(1)",
	} {
		escaped := strings.ToLower(localreview.MarkdownText(value))
		for _, autolink := range []string{"https://", "http://", "ftp://", "www.", "mailto:", "xmpp:", "javascript:", "@evil", "admin@"} {
			if strings.Contains(escaped, autolink) {
				t.Fatalf("MarkdownText(%q) = %q keeps the autolink %q", value, escaped, autolink)
			}
		}
	}
	// A value with a backtick falls back to escaped text, so it is defused too.
	if code := strings.ToLower(localreview.MarkdownCode("https://evil.example/`x")); strings.Contains(code, "https://") {
		t.Fatalf("MarkdownCode fallback kept an autolink: %q", code)
	}
	if code := localreview.MarkdownCode("dir/a_b|c.go"); code != "`dir/a_b\\|c.go`" {
		t.Fatalf("MarkdownCode = %q", code)
	}
	if code := localreview.MarkdownCode("evil`.go"); strings.Contains(code, "evil`") {
		t.Fatalf("a backtick in a path broke out of its code span: %q", code)
	}
}

// SARIF lists results in rank order (a merged duplicate after its
// representative) and carries the rank and the pre-existing class.
func TestModelReviewSARIFUsesRankOrder(t *testing.T) {
	finding := func(id, path string, start uint32, rank int, duplicateOf string, preExisting bool) localreview.ReportFinding {
		return localreview.ReportFinding{Identity: id, Fingerprint: id, Title: "t" + id, Claim: "c", Severity: diagnostics.SeverityWarning, Path: path, StartLine: start, EndLine: start, EvidenceIDs: []string{"e"}, Rank: rank, DuplicateOf: duplicateOf, PreExisting: preExisting}
	}
	report := localreview.Report{Status: "findings", CIDisposition: "blocked", RunStatus: "succeeded", Findings: []localreview.ReportFinding{
		finding("a", "a.go", 1, 3, "", false),
		finding("b", "b.go", 1, 1, "", false),
		finding("c", "c.go", 1, 2, "", true),
		finding("d", "a.go", 9, 1, "b", false),
	}}
	log, err := buildModelReviewSARIF(report)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, result := range log.Runs[0].Results {
		got = append(got, result.Fingerprints["openTrestleVerifiedFindingId/v1"])
	}
	if strings.Join(got, ",") != "b,d,c,a" {
		t.Fatalf("SARIF order = %v, want b,d,c,a", got)
	}
	if results := log.Runs[0].Results; results[0].Properties.Rank != 1 || results[2].Properties.Rank != 2 || !results[2].Properties.PreExisting || results[0].Properties.PreExisting {
		t.Fatalf("SARIF rank properties: %+v", results)
	}
}
