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
			encoded = []byte(strings.Replace(reviewOut, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1))
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
