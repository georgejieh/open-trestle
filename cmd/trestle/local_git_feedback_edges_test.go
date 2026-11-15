package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/diagnostics"
)

func TestLocalGitFeedbackRemovalAllowsExpiredMatchingInput(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	_, reviewOut := localModelExecute(t, f, f.args, 4)
	reviewPath := feedbackJourneyProtectedFile(t, "review.json", []byte(reviewOut))
	expired := rmiEncodedInputFile(t, f, f.head, time.UnixMilli(time.Now().UTC().Add(-2*time.Hour).UnixMilli()).UTC(), time.Hour)
	args := feedbackJourneyArgs(f, reviewPath, "unused", "unused")
	args = rmiRemoveFlag(args, "--feedback-input")
	args = rmiRemoveFlag(args, "--output")
	args = rmiRemoveFlag(args, "--valid-for")
	args = append(args, "--remove-input", expired)
	feedbackJourneyRun(t, args, 0)
	if _, err := os.Lstat(expired); !os.IsNotExist(err) {
		t.Fatal("expired matching input not removed")
	}
	feedbackJourneyCalls(t, f, 1)
}

func TestLocalGitFeedbackRemovalRefusesCrossHeadInput(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	_, reviewOut := localModelExecute(t, f, f.args, 4)
	reviewPath := feedbackJourneyProtectedFile(t, "review.json", []byte(reviewOut))
	other := rmiEncodedInputFile(t, f, f.base, time.UnixMilli(time.Now().UTC().UnixMilli()).UTC(), time.Hour)
	before, err := os.ReadFile(other)
	if err != nil {
		t.Fatal(err)
	}
	args := feedbackJourneyArgs(f, reviewPath, "unused", "unused")
	args = rmiRemoveFlag(args, "--feedback-input")
	args = rmiRemoveFlag(args, "--output")
	args = rmiRemoveFlag(args, "--valid-for")
	args = append(args, "--remove-input", other)
	feedbackJourneyRun(t, args, 4)
	after, err := os.ReadFile(other)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("mismatched removal altered input")
	}
	feedbackJourneyCalls(t, f, 1)
}

func TestLocalGitFindingFeedbackDoesNotBroadenLegacyInput(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	feedback := feedbackJourneyProtectedFile(t, "feedback.json", feedbackJourneyJSON(t, []any{
		map[string]any{"path": "a.go", "start_line": 4, "decision": "dismiss", "text": "Operator rationale."},
	}))
	output := rmiOutputPath(t)
	var stdout, stderr bytes.Buffer
	code := runLocalGitRetainedMemoryInput(context.Background(), rmiArgs(f, feedback, output), &stdout, &stderr)
	if code != 4 || stdout.Len() != 0 {
		t.Fatal("legacy helper accepted unbound finding disposition")
	}
	rmCLINoCalls(t, f)
}

func TestLocalGitFindingFeedbackRejectsMalformedSelector(t *testing.T) {
	for _, value := range []string{
		`[{"path":"a.go","text":"note","decision":"dismiss"}]`,
		`[{"path":"a.go","text":"note","start_line":4}]`,
		`[{"path":"a.go","text":"note","decision":"dismiss","start_line":0}]`,
		`[{"path":"a.go","text":"note","decision":"dismiss","start_line":4.0}]`,
		`[{"path":"a.go","text":"note","decision":"dismiss","start_line":4,"decision":"confirm"}]`,
	} {
		f := newLocalModelFixture(t, localModelFixtureOptions{})
		_, reviewOut := localModelExecute(t, f, f.args, 4)
		reviewPath := feedbackJourneyProtectedFile(t, "review.json", []byte(reviewOut))
		feedback := feedbackJourneyProtectedFile(t, "feedback.json", []byte(value))
		output := rmiOutputPath(t)
		feedbackJourneyRun(t, feedbackJourneyArgs(f, reviewPath, feedback, output), 4)
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatal("invalid selector created input")
		}
		feedbackJourneyCalls(t, f, 1)
	}
}

func TestLocalGitFeedbackReviewRefusesAmbiguousOrUnknownFields(t *testing.T) {
	for _, kind := range []string{"duplicate", "unknown", "null"} {
		f := newLocalModelFixture(t, localModelFixtureOptions{})
		_, reviewOut := localModelExecute(t, f, f.args, 4)
		var wire map[string]json.RawMessage
		if err := json.Unmarshal([]byte(reviewOut), &wire); err != nil {
			t.Fatal(err)
		}
		encoded := []byte(reviewOut)
		switch kind {
		case "duplicate":
			version := `"schema_version":` + string(wire["schema_version"])
			encoded = []byte(strings.Replace(reviewOut, version, version+","+version, 1))
		case "unknown":
			wire["unknown"] = json.RawMessage(`true`)
			encoded = feedbackJourneyJSON(t, wire)
		case "null":
			wire["comprehensive_clearance"] = json.RawMessage(`null`)
			encoded = feedbackJourneyJSON(t, wire)
		}
		reviewPath := feedbackJourneyProtectedFile(t, "review.json", encoded)
		feedback := rmiFeedbackFile(t, map[string]string{"a.go": "preference"})
		feedbackJourneyRun(t, feedbackJourneyArgs(f, reviewPath, feedback, rmiOutputPath(t)), 4)
		feedbackJourneyCalls(t, f, 1)
	}
}

// TestLocalGitFeedbackReviewAcceptsVersion5StyleAdviceShapes requires the
// feedback review to accept a version 5 result whose style advice is only a
// withheld language (with the unread count that every withheld language
// comes with) or only the unavailable marker, and to refuse the same style
// fields under an earlier result version.
func TestLocalGitFeedbackReviewAcceptsVersion5StyleAdviceShapes(t *testing.T) {
	oversizedModule := map[string][]byte{"go.mod": []byte("module example.test/p\n" + strings.Repeat("// padding\n", 6000))}
	for _, test := range []struct {
		name    string
		options localModelFixtureOptions
		// advice, when set, replaces the result's style fields.
		advice string
		want   string
	}{
		{name: "withheld", options: localModelFixtureOptions{extraBase: oversizedModule, extraHead: oversizedModule}, want: `,"style_withheld":[{"language":"go","changed_files":1}],"style_configuration_unread":1}`},
		{name: "unavailable", advice: `,"style_advice_unavailable":true}`, want: `,"style_advice_unavailable":true}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newLocalModelFixture(t, test.options)
			_, reviewOut := localModelExecute(t, f, f.args, 4)
			if test.advice != "" {
				const recommended = `,"style_recommendations":[{"language":"go","changed_files":1,"recommendation":"gofmt and Effective Go"}]}`
				if !strings.HasSuffix(reviewOut, recommended+"\n") {
					t.Fatalf("review result lacks the Go recommendation: %s", reviewOut)
				}
				reviewOut = strings.TrimSuffix(reviewOut, recommended+"\n") + test.advice + "\n"
			}
			if !strings.Contains(reviewOut, `"schema_version":5,`) || !strings.HasSuffix(reviewOut, test.want+"\n") || strings.Count(reviewOut, `"style_`)-strings.Count(reviewOut, `"style_detection"`) != strings.Count(test.want, `"style_`) {
				t.Fatalf("review result does not carry only the %s advice: %s", test.name, reviewOut)
			}
			feedback := rmiFeedbackFile(t, map[string]string{"a.go": "preference"})
			reviewPath := feedbackJourneyProtectedFile(t, "review.json", []byte(reviewOut))
			feedbackJourneyRun(t, feedbackJourneyArgs(f, reviewPath, feedback, rmiOutputPath(t)), 0)
			for _, version := range []string{"1", "4"} {
				earlier := strings.Replace(reviewOut, `"schema_version":5,`, `"schema_version":`+version+`,`, 1)
				earlierPath := feedbackJourneyProtectedFile(t, "review.json", []byte(earlier))
				feedbackJourneyRun(t, feedbackJourneyArgs(f, earlierPath, feedback, rmiOutputPath(t)), 4)
			}
			feedbackJourneyCalls(t, f, 1)
		})
	}
}

// TestLocalGitFeedbackReviewAcceptsVersion6TokenUsage requires the feedback
// review to accept a version 6 result, which reports token_usage, and to refuse
// token_usage under an earlier version or a version 6 result without it.
func TestLocalGitFeedbackReviewAcceptsVersion6TokenUsage(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	_, reviewOut := localModelExecute(t, f, f.args, 4)
	var wire map[string]json.RawMessage
	if err := json.Unmarshal([]byte(reviewOut), &wire); err != nil {
		t.Fatal(err)
	}
	const usage = `{"known":true,"route_attempts":2,"input_tokens":200,"output_tokens":200,"cached_input_tokens":0,"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0},"verification":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0}}`
	document := func(version, tokens string) string {
		changed := make(map[string]json.RawMessage, len(wire)+1)
		for key, value := range wire {
			changed[key] = value
		}
		changed["schema_version"] = json.RawMessage(version)
		delete(changed, "token_usage")
		if tokens != "" {
			changed["token_usage"] = json.RawMessage(tokens)
		}
		return string(feedbackJourneyJSON(t, changed)) + "\n"
	}
	feedback := rmiFeedbackFile(t, map[string]string{"a.go": "preference"})
	for _, test := range []struct {
		name, version, tokens string
		want                  int
	}{
		{"version 6 with token usage", "6", usage, 0},
		{"version 6 without token usage", "6", "", 4},
		{"version 6 with null token usage", "6", "null", 4},
		{"version 6 with non-object token usage", "6", "true", 4},
		{"version 5 with token usage", "5", usage, 4},
		{"version 1 with token usage", "1", usage, 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			reviewPath := feedbackJourneyProtectedFile(t, "review.json", []byte(document(test.version, test.tokens)))
			feedbackJourneyRun(t, feedbackJourneyArgs(f, reviewPath, feedback, rmiOutputPath(t)), test.want)
		})
	}
	feedbackJourneyCalls(t, f, 1)
}

// TestLocalGitFeedbackReviewRefusesStyleAdviceNoReviewEmits requires the
// feedback review to refuse a version 5 result whose style advice a review
// could not have recorded.
func TestLocalGitFeedbackReviewRefusesStyleAdviceNoReviewEmits(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	_, reviewOut := localModelExecute(t, f, f.args, 4)
	const recommended = `"style_recommendations":[{"language":"go","changed_files":1,"recommendation":"gofmt and Effective Go"}]`
	if !strings.Contains(reviewOut, recommended) {
		t.Fatalf("review result lacks the Go recommendation: %s", reviewOut)
	}
	feedback := rmiFeedbackFile(t, map[string]string{"a.go": "preference"})
	for name, tampered := range map[string]string{
		"unknown language":                       strings.Replace(reviewOut, `"language":"go"`, `"language":"cobol"`, 1),
		"recommendation text not from the table": strings.Replace(reviewOut, `"recommendation":"gofmt and Effective Go"`, `"recommendation":"gofmt"`, 1),
		"withheld without unread count":          strings.Replace(reviewOut, recommended, `"style_withheld":[{"language":"go","changed_files":1}]`, 1),
	} {
		if tampered == reviewOut {
			t.Fatalf("%s fixture did not change the result", name)
		}
		reviewPath := feedbackJourneyProtectedFile(t, "review.json", []byte(tampered))
		feedbackJourneyRun(t, feedbackJourneyArgs(f, reviewPath, feedback, rmiOutputPath(t)), 4)
	}
	feedbackJourneyCalls(t, f, 1)
}

func TestLocalGitFeedbackRejectsAmbiguousCanonicalFindingSelection(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	_, reviewOut := localModelExecute(t, f, f.args, 4)
	var wire map[string]json.RawMessage
	if err := json.Unmarshal([]byte(reviewOut), &wire); err != nil {
		t.Fatal(err)
	}
	set, err := diagnostics.ParseSet(wire["diagnostics"])
	if err != nil || len(set.Findings()) != 1 {
		t.Fatalf("canonical finding unavailable: %v", err)
	}
	first := set.Findings()[0]
	second, err := diagnostics.NewFinding(first.SourceIdentity(), strings.Repeat("b", 64), "Second finding", first.Message(), first.Severity(), first.Path(), first.StartLine(), first.EndLine(), first.EvidenceIDs())
	if err != nil {
		t.Fatal(err)
	}
	ambiguous, err := diagnostics.NewSetWithSourceCoverage(set.Scope(), set.SnapshotIdentity(), set.HeadRevision(), set.VerifiedSetIdentity(), set.VerificationContextIdentity(), set.CandidateCount()+1, set.RejectedCount(), set.InconclusiveCount(), set.SourceAnalyzedCount(), set.SourceSelectedCount(), set.SourceOmittedCount(), []diagnostics.Finding{first, second})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := diagnostics.EncodeSet(ambiguous)
	if err != nil {
		t.Fatal(err)
	}
	wire["diagnostics"] = encoded
	reviewPath := feedbackJourneyProtectedFile(t, "review.json", feedbackJourneyJSON(t, wire))
	feedback := feedbackJourneyProtectedFile(t, "feedback.json", feedbackJourneyJSON(t, []any{map[string]any{
		"path": first.Path(), "start_line": first.StartLine(), "decision": "dismiss", "text": "Operator rationale.",
	}}))
	output := rmiOutputPath(t)
	feedbackJourneyRun(t, feedbackJourneyArgs(f, reviewPath, feedback, output), 4)
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatal("ambiguous finding selection created input")
	}
	feedbackJourneyCalls(t, f, 1)
}
