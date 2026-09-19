package review

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
)

func verificationFixture(t *testing.T, document string) (provider.Response, CandidateBatch, []evidence.EvidenceItem) {
	t.Helper()
	candidateResponse, snapshot, items := candidateFixture(t, validCandidateDocument())
	candidates, err := ParseCandidateBatch(candidateResponse, snapshot, items)
	if err != nil {
		t.Fatal(err)
	}
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	if err != nil {
		t.Fatal(err)
	}
	return response, candidates, items
}

func validVerificationDocument(candidateID string) string {
	return fmt.Sprintf(`{"schema_version":1,"verdicts":[{"candidate_id":%q,"outcome":"verified","severity":"high","rationale":"The cited span confirms the discarded error.","evidence_ids":["evidence-1"]}]}`, candidateID)
}

func TestParseVerificationBatchBindsEveryCandidateAndEvidence(t *testing.T) {
	_, candidates, _ := verificationFixture(t, `{"schema_version":1,"verdicts":[]}`)
	response, candidates, items := verificationFixture(t, validVerificationDocument(candidates.Findings()[0].Identity()))
	batch, err := ParseVerificationBatch(response, candidates, items)
	if err != nil {
		t.Fatal(err)
	}
	results := batch.Results()
	if batch.Identity() == "" || batch.ResponseIdentity() != response.Identity() || batch.CandidateBatchIdentity() != candidates.Identity() || batch.SnapshotIdentity() != candidates.SnapshotIdentity() || len(results) != 1 || batch.Validate() != nil {
		t.Fatalf("verification batch did not round trip: %#v", batch)
	}
	result := results[0]
	if result.Identity() == "" || result.CandidateIdentity() != candidates.Findings()[0].Identity() || result.Outcome() != VerificationVerified || result.FinalSeverity() != SeverityHigh || result.Rationale() != "The cited span confirms the discarded error." || !reflect.DeepEqual(result.EvidenceIDs(), []string{"evidence-1"}) || result.Validate() != nil {
		t.Fatalf("verification result did not round trip: %#v", result)
	}
	results[0] = VerificationResult{}
	ids := result.EvidenceIDs()
	ids[0] = "changed"
	if batch.Results()[0].Identity() != result.Identity() || result.EvidenceIDs()[0] != "evidence-1" {
		t.Fatal("verification values exposed mutable state")
	}
	if fmt.Sprint(batch) != "verification batch" || fmt.Sprintf("%#v", batch) != "review.VerificationBatch{<redacted>}" || strings.Contains(fmt.Sprint(result), "discarded") {
		t.Fatalf("verification formatting leaked: %v / %#v / %v", batch, batch, result)
	}
}

func TestParseVerificationBatchAcceptsEmptyCandidateBatch(t *testing.T) {
	candidateResponse, snapshot, items := candidateFixture(t, `{"schema_version":1,"candidates":[]}`)
	candidates, _ := ParseCandidateBatch(candidateResponse, snapshot, nil)
	part, _ := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(`{"schema_version":1,"verdicts":[]}`))
	response, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	batch, err := ParseVerificationBatch(response, candidates, items)
	if err != nil || batch.Identity() == "" || batch.Results() != nil || batch.Validate() != nil {
		t.Fatalf("empty verification batch = (%#v, %v)", batch, err)
	}
}

func TestVerificationSyntaxMatchesPublishedFixtures(t *testing.T) {
	encoded, err := os.ReadFile("../../schemas/review/fixtures/model-verification-batch-v1.cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Cases []struct {
			Name          string          `json:"name"`
			ExpectedValid bool            `json:"expected_valid"`
			Instance      json.RawMessage `json:"instance"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, test := range manifest.Cases {
		t.Run(test.Name, func(t *testing.T) {
			err := ValidateVerificationDocumentSyntax(test.Instance)
			if (err == nil) != test.ExpectedValid {
				t.Fatalf("ValidateVerificationDocumentSyntax() = %v, expected_valid=%t", err, test.ExpectedValid)
			}
		})
	}
}

func TestParseVerificationBatchRejectsMissingDuplicateAndUnknownCandidates(t *testing.T) {
	_, candidates, items := verificationFixture(t, `{"schema_version":1,"verdicts":[]}`)
	candidateID := candidates.Findings()[0].Identity()
	for _, test := range []struct {
		name, document string
		want           error
	}{
		{"missing", `{"schema_version":1,"verdicts":[]}`, ErrVerificationCandidateSetMismatch},
		{"unknown", validVerificationDocument(strings.Repeat("f", 64)), ErrVerificationCandidateNotAllowed},
		{"duplicate", fmt.Sprintf(`{"schema_version":1,"verdicts":[{"candidate_id":%q,"outcome":"rejected","severity":"none","rationale":"No issue.","evidence_ids":[]},{"candidate_id":%q,"outcome":"rejected","severity":"none","rationale":"No issue.","evidence_ids":[]}]}`, candidateID, candidateID), ErrDuplicateVerificationCandidate},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, _, _ := verificationFixture(t, test.document)
			batch, err := ParseVerificationBatch(response, candidates, items)
			if !errors.Is(err, test.want) || batch.Identity() != "" {
				t.Fatalf("ParseVerificationBatch() = (%#v, %v), want %v", batch, err, test.want)
			}
		})
	}
}

func TestParseVerificationBatchEnforcesVerifiedEvidence(t *testing.T) {
	_, candidates, items := verificationFixture(t, `{"schema_version":1,"verdicts":[]}`)
	candidateID := candidates.Findings()[0].Identity()
	missing := strings.Replace(validVerificationDocument(candidateID), "evidence-1", "other-evidence", 1)
	response, _, _ := verificationFixture(t, missing)
	if batch, err := ParseVerificationBatch(response, candidates, items); !errors.Is(err, ErrVerificationEvidenceNotAllowed) || batch.Identity() != "" {
		t.Fatalf("missing evidence = (%#v, %v)", batch, err)
	}
	otherRange, _ := evidence.NewSourceRange("internal/other.go", 1, 1)
	otherItem, _ := evidence.NewEvidenceItem("other-evidence", evidence.EvidenceKindSource, strings.Repeat("c", 64), otherRange)
	items = append(items, otherItem)
	if batch, err := ParseVerificationBatch(response, candidates, items); !errors.Is(err, ErrVerificationEvidenceRangeMismatch) || batch.Identity() != "" {
		t.Fatalf("range mismatch = (%#v, %v)", batch, err)
	}
}

func TestParseVerificationBatchRejectsUnsupportedEnvelopeAndForgery(t *testing.T) {
	_, candidates, items := verificationFixture(t, `{"schema_version":1,"verdicts":[]}`)
	document := validVerificationDocument(candidates.Findings()[0].Identity())
	response, _, _ := verificationFixture(t, document)
	part := response.Parts()[0]
	lengthResponse, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishLength, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	if batch, err := ParseVerificationBatch(lengthResponse, candidates, items); !errors.Is(err, ErrInvalidVerificationResponseEnvelope) || batch.Identity() != "" {
		t.Fatalf("length response = (%#v, %v)", batch, err)
	}
	batch, _ := ParseVerificationBatch(response, candidates, items)
	forged := batch
	forged.identity = strings.Repeat("f", 64)
	if !errors.Is(forged.Validate(), ErrInvalidVerificationBatchIdentity) {
		t.Fatal("forged batch identity accepted")
	}
}

func TestVerificationOutcomeRoundTrips(t *testing.T) {
	for _, token := range []string{"verified", "rejected", "inconclusive"} {
		outcome, err := ParseVerificationOutcome(token)
		if err != nil || outcome.String() != token || outcome.Validate() != nil {
			t.Fatalf("outcome %q = (%v, %v)", token, outcome, err)
		}
	}
}
