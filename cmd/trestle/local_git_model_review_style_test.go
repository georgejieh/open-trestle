package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// TestRunLocalGitModelReviewSetCarriesGeneralStyleAdviceOnce checks that a
// review set reports the general member's style advice once, in JSON and
// text, and that a set without advice carries no style field or line.
func TestRunLocalGitModelReviewSetCarriesGeneralStyleAdviceOnce(t *testing.T) {
	goModule := map[string][]byte{"go.mod": []byte("module example.test/p\n")}
	const jsonAdvice = `,"style_recommendations":[{"language":"go","changed_files":1,"recommendation":"gofmt and Effective Go"}]}` + "\n"
	const textAdvice = "style: no declared Go style for 1 changed file; consider gofmt and Effective Go, and commit its configuration\ncomprehensive clearance: false\n"
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
			} else if hasStyleAdviceJSON(encoded) || !strings.HasSuffix(encoded, `"comprehensive_clearance":false}`+"\n") {
				t.Fatalf("set JSON without advice changed shape:\n%s", encoded)
			}
			_, text := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter,backend", "--format", "text"}, 4)
			if strings.Contains(text, textAdvice) != test.advising || strings.Count(text, "style: ") != map[bool]int{true: 1, false: 0}[test.advising] {
				t.Fatalf("set text style advice mismatch:\n%s", text)
			}
		})
	}
}

// TestLocalGitInvestigationResultCarriesStyleAdvice checks that an
// investigation result reports style advice under schema version 5 with its
// investigation block, and stays version 2 when the base declares the style.
func TestLocalGitInvestigationResultCarriesStyleAdvice(t *testing.T) {
	for _, test := range []struct {
		name     string
		goModule bool
		version  int
	}{
		{"no go.mod", false, 6},
		{"go.mod in base", true, 6},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			f, _, policy, path := newInvestigationFixture(t, "", cancel)
			writeInvestigationPolicy(t, path, policy)
			base := map[string][]byte{"a.go": []byte("package p\nfunc Changed(x int) int { if x == 0 { return 0 }; return 10 / x }\n"), "notes.txt": []byte(investigationNotes)}
			head := map[string][]byte{"a.go": []byte("package p\nfunc Changed(x int) int { return 10 / x }\n"), "notes.txt": base["notes.txt"]}
			if test.goModule {
				base["go.mod"], head["go.mod"] = []byte("module example.test/p\n"), []byte("module example.test/p\n")
			}
			f.objects, f.base, f.head = writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, base, head)
			args := rmiReplaceFlag(f.args, "--objects-root", f.objects)
			args = rmiReplaceFlag(args, "--base-revision-digest", f.base)
			args = rmiReplaceFlag(replaceLocalGitChangeValue(rmiReplaceFlag(args, "--head-revision-digest", f.head), "--timeout", "30s"), "--format", "json")
			var stdout, stderr bytes.Buffer
			code := runWithContext(ctx, args, &stdout, &stderr)
			var receipt struct {
				Version       int             `json:"schema_version"`
				Status        string          `json:"status"`
				Investigation json.RawMessage `json:"investigation"`
			}
			if code != 4 || json.Unmarshal(stdout.Bytes(), &receipt) != nil || receipt.Version != test.version || receipt.Status != "findings" || len(receipt.Investigation) == 0 || string(receipt.Investigation) == "null" {
				t.Fatalf("investigation exit=%d stderr=%q result=%s", code, stderr.String(), stdout.String())
			}
			const advice = `,"style_recommendations":[{"language":"go","changed_files":1,"recommendation":"gofmt and Effective Go"}]}` + "\n"
			if strings.HasSuffix(stdout.String(), advice) != !test.goModule || strings.Contains(stdout.String(), `"style_`) == test.goModule {
				t.Fatalf("investigation style advice mismatch: %s", stdout.String())
			}
		})
	}
}

// TestModelReviewSARIFCarriesStyleAdviceAtRunLevel requires SARIF to carry the
// style advice as a run property and a note notification, never as a result:
// results stay exactly the verified findings.
func TestModelReviewSARIFCarriesStyleAdviceAtRunLevel(t *testing.T) {
	goModule := map[string][]byte{"go.mod": []byte("module example.test/p\n")}
	const note = "style: no declared Go style for 1 changed file; consider gofmt and Effective Go, and commit its configuration"
	for _, test := range []struct {
		name     string
		options  localModelFixtureOptions
		advising bool
	}{
		{"no go.mod", localModelFixtureOptions{}, true},
		{"go.mod in base", localModelFixtureOptions{extraBase: goModule, extraHead: goModule}, false},
	} {
		for _, set := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s set=%t", test.name, set), func(t *testing.T) {
				f := newLocalModelFixture(t, test.options)
				var text string
				if set {
					_, text = runLocalModelSet(t, f, []string{"--specialists", "bug_hunter", "--format", "sarif"}, 4)
				} else {
					var stdout, stderr bytes.Buffer
					if code := run(replaceLocalGitChangeValue(f.args, "--format", "sarif"), &stdout, &stderr); code != 4 || stderr.Len() != 0 {
						t.Fatalf("sarif exit=%d stderr=%q", code, stderr.String())
					}
					text = stdout.String()
				}
				var log struct {
					Runs []struct {
						Results     []json.RawMessage `json:"results"`
						Invocations []struct {
							Notifications []struct {
								Level   string `json:"level"`
								Message struct {
									Text string `json:"text"`
								} `json:"message"`
							} `json:"toolExecutionNotifications"`
						} `json:"invocations"`
						Properties struct {
							StyleAdvice *struct {
								Recommendations []struct {
									Language       string `json:"language"`
									ChangedFiles   int    `json:"changedFiles"`
									Recommendation string `json:"recommendation"`
								} `json:"recommendations"`
							} `json:"trestleStyleAdvice"`
						} `json:"properties"`
					} `json:"runs"`
				}
				if err := json.Unmarshal([]byte(text), &log); err != nil || len(log.Runs) != 1 || len(log.Runs[0].Results) != 1 || len(log.Runs[0].Invocations) != 1 {
					t.Fatalf("SARIF is not one run with the one verified finding: %v\n%s", err, text)
				}
				reviewRun := log.Runs[0]
				notes := 0
				for _, notification := range reviewRun.Invocations[0].Notifications {
					if strings.HasPrefix(notification.Message.Text, "style: ") {
						notes++
						if notification.Level != "note" || notification.Message.Text != note {
							t.Fatalf("style notification = %+v", notification)
						}
					}
				}
				advice := reviewRun.Properties.StyleAdvice
				if test.advising {
					if notes != 1 || advice == nil || len(advice.Recommendations) != 1 || advice.Recommendations[0].Language != "go" || advice.Recommendations[0].ChangedFiles != 1 || advice.Recommendations[0].Recommendation != "gofmt and Effective Go" {
						t.Fatalf("SARIF style advice = %+v notes=%d", advice, notes)
					}
				} else if notes != 0 || advice != nil || strings.Contains(text, "trestleStyleAdvice") {
					t.Fatalf("SARIF without advice carries style: %s", text)
				}
			})
		}
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
		{"no go.mod", localModelFixtureOptions{}, 6, true},
		{"go.mod in base", localModelFixtureOptions{extraBase: goModule, extraHead: goModule}, 6, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLocalModelFixture(t, test.options)
			result, encoded := localModelExecute(t, f, f.args, 4)
			if result.Version != test.version || result.Status != "findings" || result.CI != "blocked" || strings.HasSuffix(encoded, jsonAdvice) != test.advising || hasStyleAdviceJSON(encoded) != test.advising {
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

// hasStyleAdviceJSON reports a style advice member in a JSON result or set;
// the walkthrough's style_detection entry is not advice.
func hasStyleAdviceJSON(encoded string) bool {
	for _, key := range []string{`"style_recommendations"`, `"style_withheld"`, `"style_configuration_unread"`, `"style_advice_unavailable"`} {
		if strings.Contains(encoded, key) {
			return true
		}
	}
	return false
}
