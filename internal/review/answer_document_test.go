package review

import (
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// Every answer below is a synthetic fixture.

func twoCandidateBatch(t *testing.T) (CandidateBatch, []string) {
	t.Helper()
	second := strings.TrimSuffix(validCandidateDocument(), `]}`) + `,{"title":"Second issue","claim":"The close error is discarded.","severity_hint":"medium","source_range":{"source_id":"evidence-1","start_line":15,"end_line":15},"evidence_ids":["evidence-1"]}]}`
	response, snapshot, items := candidateFixture(t, second)
	candidates, err := ParseCandidateBatch(response, snapshot, items)
	if err != nil || len(candidates.Findings()) != 2 {
		t.Fatalf("candidates=%d err=%v", len(candidates.Findings()), err)
	}
	return candidates, []string{candidates.Findings()[0].Identity(), candidates.Findings()[1].Identity()}
}

func rejectedVerdict(label string) string {
	return `{"candidate_id":"` + label + `","outcome":"rejected","severity":"none","rationale":"No issue.","evidence_ids":[]}`
}

// A verdict names its candidate by the request's label, in any order, and
// the host maps each label back to the candidate identity.
func TestVerificationLabelsMapBackToCandidateIdentities(t *testing.T) {
	candidates, identities := twoCandidateBatch(t)
	_, _, items := candidateFixture(t, validCandidateDocument())
	document := `{"schema_version":1,"verdicts":[` + rejectedVerdict("c2") + `,` + strings.Replace(rejectedVerdict("c1"), "No issue.", "First.", 1) + `]}`
	batch, err := ParseVerificationBatch(stoppedResponse(t, provider.ResponsePartStructuredData, document), candidates, items)
	if err != nil {
		t.Fatal(err)
	}
	results := batch.Results()
	if len(results) != 2 || results[0].CandidateIdentity() != identities[0] || results[0].Rationale() != "First." || results[1].CandidateIdentity() != identities[1] {
		t.Fatalf("labels did not map back: %v", batch)
	}
	for _, test := range []struct {
		name, verdicts string
		want           error
	}{
		{"a label the request does not have", rejectedVerdict("c1") + `,` + rejectedVerdict("c3"), ErrVerificationCandidateNotAllowed},
		{"the full candidate identity", rejectedVerdict("c1") + `,` + rejectedVerdict(identities[1]), ErrVerificationCandidateNotAllowed},
		{"a zero-padded label", rejectedVerdict("c1") + `,` + rejectedVerdict("c02"), ErrVerificationCandidateNotAllowed},
		{"a duplicated label", rejectedVerdict("c1") + `,` + rejectedVerdict("c1"), ErrDuplicateVerificationCandidate},
		{"a missing label", rejectedVerdict("c2"), ErrVerificationCandidateSetMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := stoppedResponse(t, provider.ResponsePartStructuredData, `{"schema_version":1,"verdicts":[`+test.verdicts+`]}`)
			if _, err := ParseVerificationBatch(response, candidates, items); !errors.Is(err, test.want) || !errors.Is(err, ErrModelOutputInvalid) {
				t.Fatalf("err=%v, want %v", err, test.want)
			}
		})
	}
}

// One complete JSON object followed only by text that is not JSON is read as
// that object. Leading text, a second document, an incomplete document, or a
// tail that is JSON stay refused.
func TestAnswerDocumentIgnoresOnlyANonJSONTail(t *testing.T) {
	document := validVerificationDocument("c1")
	_, candidates, items := verificationFixture(t, document)
	for _, text := range []string{document + "</parameter_never_used_51bce0c7>", document + "\n<|return|>\n", "  " + document + " trailing note"} {
		if _, err := ParseVerificationBatch(stoppedResponse(t, provider.ResponsePartAssistantText, text), candidates, items); err != nil {
			t.Fatalf("%q refused: %v", text, err)
		}
	}
	for _, text := range []string{
		"<|channel|>final<|message|>" + document,
		"Here is the answer: " + document,
		document + document,
		document + ` {"schema_version":1}`,
		document + ` ["x"]`,
		document + ` 7`,
		strings.TrimSuffix(document, "}") + " trailing",
	} {
		_, err := ParseVerificationBatch(stoppedResponse(t, provider.ResponsePartAssistantText, text), candidates, items)
		if problem, _ := ModelOutputProblemOf(err); !errors.Is(err, ErrInvalidVerificationResponseEnvelope) || problem != ModelOutputNotJSON {
			t.Fatalf("%q: err=%v problem=%q", text, err, problem)
		}
	}
	// The tail is dropped before the same content checks.
	if _, err := ParseVerificationBatch(stoppedResponse(t, provider.ResponsePartAssistantText, validVerificationDocument("c2")+"<|end|>"), candidates, items); !errors.Is(err, ErrVerificationCandidateNotAllowed) {
		t.Fatalf("content checks skipped: %v", err)
	}
	// Generation answers go through the same rule.
	_, snapshot, candidateItems := candidateFixture(t, validCandidateDocument())
	if _, err := ParseCandidateBatch(stoppedResponse(t, provider.ResponsePartAssistantText, validCandidateDocument()+"<|return|>"), snapshot, candidateItems); err != nil {
		t.Fatalf("candidate answer with a tail refused: %v", err)
	}
	if _, err := ParseCandidateBatch(stoppedResponse(t, provider.ResponsePartAssistantText, "Answer: "+validCandidateDocument()), snapshot, candidateItems); !errors.Is(err, ErrInvalidCandidateResponseEnvelope) {
		t.Fatalf("leading text accepted: %v", err)
	}
}
