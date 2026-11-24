package review

import (
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// Every document below is a synthetic fixture. A parse failure the model's
// answer caused is marked ErrModelOutputInvalid and keeps its specific error;
// a host input that fails its own check is never marked.

func stoppedResponse(t *testing.T, kind provider.ResponsePartKind, payload string) provider.Response {
	t.Helper()
	mediaType := "text/plain; charset=utf-8"
	if kind == provider.ResponsePartStructuredData {
		mediaType = "application/json"
	}
	part, err := provider.NewResponsePart(kind, mediaType, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestCandidateParseMarksFailuresTheAnswerCaused(t *testing.T) {
	_, snapshot, items := candidateFixture(t, validCandidateDocument())
	wrapped := "<|start|>assistant<|channel|>final <|constrain|>json<|message|>" + validCandidateDocument() + "<|return|>"
	for _, test := range []struct {
		name     string
		response provider.Response
		specific error
		problem  ModelOutputProblem
	}{
		{"chat-template tokens around the JSON", stoppedResponse(t, provider.ResponsePartAssistantText, wrapped), ErrInvalidCandidateResponseEnvelope, ModelOutputNotJSON},
		{"a control character inside a JSON string", stoppedResponse(t, provider.ResponsePartAssistantText, strings.Replace(validCandidateDocument(), "discarded.", "discarded.\x01", 1)), ErrInvalidCandidateResponseEnvelope, ModelOutputNotJSON},
		{"a refusal", stoppedResponse(t, provider.ResponsePartRefusal, "I cannot review this."), ErrInvalidCandidateResponseEnvelope, ModelOutputRefusal},
		{"the wrong shape", stoppedResponse(t, provider.ResponsePartStructuredData, `{"schema_version":1,"findings":[]}`), ErrInvalidCandidateDocumentShape, ModelOutputWrongShape},
		{"a location outside the request", stoppedResponse(t, provider.ResponsePartStructuredData, strings.Replace(validCandidateDocument(), `"start_line":12,"end_line":13`, `"start_line":21,"end_line":21`, 1)), ErrCandidateRangeNotSupported, ModelOutputEvidenceMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseCandidateBatch(test.response, snapshot, items)
			problem, marked := ModelOutputProblemOf(err)
			if !errors.Is(err, ErrModelOutputInvalid) || !errors.Is(err, test.specific) || !marked || problem != test.problem {
				t.Fatalf("err=%v problem=%q, want %v marked as %q", err, problem, test.specific, test.problem)
			}
		})
	}
	// A host evidence set that fails its own check is not the model's doing.
	response, _, _ := candidateFixture(t, validCandidateDocument())
	duplicate := append(append([]evidence.EvidenceItem{}, items...), items...)
	if _, err := ParseCandidateBatch(response, snapshot, duplicate); err == nil || errors.Is(err, ErrModelOutputInvalid) {
		t.Fatalf("a host input failure was marked: %v", err)
	}
	if _, err := ParseCandidateBatch(response, ReviewSnapshot{}, items); err == nil || errors.Is(err, ErrModelOutputInvalid) {
		t.Fatalf("an invalid snapshot was marked: %v", err)
	}
	if _, err := ParseCandidateBatch(response, snapshot, items); err != nil {
		t.Fatalf("a valid answer was refused: %v", err)
	}
}

func TestVerificationParseMarksFailuresTheAnswerCaused(t *testing.T) {
	_, candidates, items := verificationFixture(t, `{"schema_version":1,"verdicts":[]}`)
	document := validVerificationDocument("c1")
	for _, test := range []struct {
		name     string
		response provider.Response
		specific error
		problem  ModelOutputProblem
	}{
		{"chat-template tokens around the JSON", stoppedResponse(t, provider.ResponsePartAssistantText, "<|channel|>final<|message|>"+document+"<|return|>"), ErrInvalidVerificationResponseEnvelope, ModelOutputNotJSON},
		{"the wrong shape", stoppedResponse(t, provider.ResponsePartStructuredData, `{"schema_version":1,"results":[]}`), ErrInvalidVerificationDocumentShape, ModelOutputWrongShape},
		{"a missing verdict", stoppedResponse(t, provider.ResponsePartStructuredData, `{"schema_version":1,"verdicts":[]}`), ErrVerificationCandidateSetMismatch, ModelOutputCandidateSetMismatch},
		{"an unknown candidate label", stoppedResponse(t, provider.ResponsePartStructuredData, strings.Replace(document, `"c1"`, `"c2"`, 1)), ErrVerificationCandidateNotAllowed, ModelOutputUnknownCandidate},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseVerificationBatch(test.response, candidates, items)
			problem, marked := ModelOutputProblemOf(err)
			if !errors.Is(err, ErrModelOutputInvalid) || !errors.Is(err, test.specific) || !marked || problem != test.problem {
				t.Fatalf("err=%v problem=%q, want %v marked as %q", err, problem, test.specific, test.problem)
			}
		})
	}
	valid := stoppedResponse(t, provider.ResponsePartStructuredData, document)
	if _, err := ParseVerificationBatch(valid, CandidateBatch{}, items); err == nil || errors.Is(err, ErrModelOutputInvalid) {
		t.Fatalf("an invalid candidate batch was marked: %v", err)
	}
	if _, err := ParseVerificationBatch(valid, candidates, items); err != nil {
		t.Fatalf("a valid answer was refused: %v", err)
	}
}
