package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRunLocalGitModelReviewSetCarriesGeneralStyleAdviceOnce checks that a
// review set reports the general member's style advice once, in JSON and
// text, and that a set without advice carries no style field or line.
func TestRunLocalGitModelReviewSetCarriesGeneralStyleAdviceOnce(t *testing.T) {
	goModule := map[string][]byte{"go.mod": []byte("module example.test/p\n")}
	const jsonAdvice = `,"style_recommendations":[{"language":"go","changed_files":1,"recommendation":"gofmt and Effective Go"}]}` + "\n"
	const textAdvice = "style: no declared Go style for 1 changed file; consider gofmt and Effective Go, and commit its configuration\nlimitations: "
	for _, test := range []struct {
		name     string
		options  localModelFixtureOptions
		advising bool
	}{
		{"no go.mod", localModelFixtureOptions{}, true},
		{"go.mod in base", localModelFixtureOptions{extraBase: goModule, extraHead: goModule}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLocalModelFixture(t, test.options)
			receipt, encoded := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter,backend"}, 4)
			if len(receipt.Members) != 3 || receipt.Status != "findings" || receipt.CI != "blocked" {
				t.Fatalf("set did not run three members to findings: %+v", receipt)
			}
			if test.advising {
				if !strings.HasSuffix(encoded, jsonAdvice) || strings.Count(encoded, "style_recommendations") != 1 || strings.Contains(encoded, "style_configuration_unread") {
					t.Fatalf("set JSON does not carry the general advice exactly once:\n%s", encoded)
				}
			} else if strings.Contains(encoded, "style_") || !strings.HasSuffix(encoded, `"comprehensive_clearance":false}`+"\n") {
				t.Fatalf("set JSON without advice changed shape:\n%s", encoded)
			}
			_, text := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter,backend", "--format", "text"}, 4)
			if strings.Contains(text, textAdvice) != test.advising || strings.Count(text, "style: ") != map[bool]int{true: 1, false: 0}[test.advising] {
				t.Fatalf("set text style advice mismatch:\n%s", text)
			}
		})
	}
}

// TestRunLocalGitModelReviewRecommendsStyleWithoutBlocking checks the style
// recommendation in the command's JSON and text output, and that it changes no
// exit code under any policy.
func TestRunLocalGitModelReviewRecommendsStyleWithoutBlocking(t *testing.T) {
	goModule := map[string][]byte{"go.mod": []byte("module example.test/p\n")}
	const jsonAdvice = `,"style_recommendations":[{"language":"go","changed_files":1,"recommendation":"gofmt and Effective Go"}]}` + "\n"
	const textAdvice = "style: no declared Go style for 1 changed file; consider gofmt and Effective Go, and commit its configuration\n"
	for _, test := range []struct {
		name     string
		options  localModelFixtureOptions
		version  int
		advising bool
	}{
		{"no go.mod", localModelFixtureOptions{}, 5, true},
		{"go.mod in base", localModelFixtureOptions{extraBase: goModule, extraHead: goModule}, 4, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLocalModelFixture(t, test.options)
			result, encoded := localModelExecute(t, f, f.args, 4)
			if result.Version != test.version || result.Status != "findings" || result.CI != "blocked" || strings.HasSuffix(encoded, jsonAdvice) != test.advising || strings.Contains(encoded, "style_") != test.advising {
				t.Fatalf("JSON version=%d status=%s advice=%t: %s", result.Version, result.Status, strings.HasSuffix(encoded, jsonAdvice), encoded)
			}
			var stdout, stderr bytes.Buffer
			if code := run(replaceLocalGitChangeValue(f.args, "--format", "text"), &stdout, &stderr); code != 4 || stderr.Len() != 0 {
				t.Fatalf("text exit=%d stderr=%q", code, stderr.String())
			}
			if strings.Contains(stdout.String(), textAdvice) != test.advising || strings.Contains(stdout.String(), "style: ") != test.advising {
				t.Fatalf("text output style advice mismatch:\n%s", stdout.String())
			}
			for policy, want := range map[string]int{"default": 4, "findings": 4, "strict": 4, "always-zero": 0} {
				stdout.Reset()
				if code := run(append(append([]string(nil), f.args...), "--exit-code-policy", policy), &stdout, &stderr); code != want {
					t.Fatalf("exit-code policy %s exit=%d want=%d", policy, code, want)
				}
			}
		})
	}
}
