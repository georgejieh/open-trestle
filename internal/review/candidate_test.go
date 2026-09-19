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

func candidateFixture(t *testing.T, document string) (provider.Response, ReviewSnapshot, []evidence.EvidenceItem) {
	t.Helper()
	sourceRange, err := evidence.NewSourceRange("internal/example.go", 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewReviewSnapshot("workspace", strings.Repeat("a", 64), []evidence.SourceRange{sourceRange})
	if err != nil {
		t.Fatal(err)
	}
	item, err := evidence.NewEvidenceItem("evidence-1", evidence.EvidenceKindSource, strings.Repeat("b", 64), sourceRange)
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
	return response, snapshot, []evidence.EvidenceItem{item}
}

func validCandidateDocument() string {
	return `{"schema_version":1,"candidates":[{"title":"Unchecked write error","claim":"The write error is discarded.","severity_hint":"high","source_range":{"source_id":"evidence-1","start_line":12,"end_line":13},"evidence_ids":["evidence-1"]}]}`
}

func TestParseCandidateBatchBindsResponseSnapshotAndEvidence(t *testing.T) {
	response, snapshot, items := candidateFixture(t, validCandidateDocument())
	batch, err := ParseCandidateBatch(response, snapshot, items)
	if err != nil {
		t.Fatal(err)
	}
	findings := batch.Findings()
	if batch.Identity() == "" || batch.ResponseIdentity() != response.Identity() || batch.SnapshotIdentity() != snapshot.Identity() || len(findings) != 1 || batch.Validate() != nil {
		t.Fatalf("candidate batch did not round trip: %#v", batch)
	}
	finding := findings[0]
	if finding.Identity() == "" || finding.Ordinal() != 1 || finding.Title() != "Unchecked write error" || finding.Claim() != "The write error is discarded." || finding.SeverityHint() != SeverityHigh || finding.SourceReferenceID() != "evidence-1" || finding.SourceRange().Path() != "internal/example.go" || !reflect.DeepEqual(finding.EvidenceIDs(), []string{"evidence-1"}) || finding.Validate() != nil {
		t.Fatalf("candidate finding did not round trip: %#v", finding)
	}
	findings[0] = CandidateFinding{}
	evidenceIDs := finding.EvidenceIDs()
	evidenceIDs[0] = "changed"
	if len(batch.Findings()) != 1 || finding.EvidenceIDs()[0] != "evidence-1" {
		t.Fatal("candidate values exposed mutable state")
	}
	if fmt.Sprint(batch) != "candidate finding batch" || fmt.Sprintf("%#v", batch) != "review.CandidateBatch{<redacted>}" || strings.Contains(fmt.Sprint(batch), "Unchecked") || fmt.Sprint(finding) != "candidate finding" {
		t.Fatalf("candidate formatting leaked: %v / %#v / %v", batch, batch, finding)
	}
}

func TestParseCandidateBatchAllowsExplicitEmptyCandidateSet(t *testing.T) {
	response, snapshot, _ := candidateFixture(t, `{"schema_version":1,"candidates":[]}`)
	batch, err := ParseCandidateBatch(response, snapshot, nil)
	if err != nil || batch.Identity() == "" || batch.Findings() != nil || batch.Validate() != nil {
		t.Fatalf("empty candidate batch = (%#v, %v)", batch, err)
	}
}

func TestCandidateSyntaxMatchesPublishedFixtures(t *testing.T) {
	encoded, err := os.ReadFile("../../schemas/review/fixtures/model-candidate-batch-v1.cases.json")
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
			err := ValidateCandidateDocumentSyntax(test.Instance)
			if (err == nil) != test.ExpectedValid {
				t.Fatalf("ValidateCandidateDocumentSyntax() = %v, expected_valid=%t", err, test.ExpectedValid)
			}
		})
	}
}

func TestCandidateSyntaxRejectsDuplicateAndCaseVariantKeys(t *testing.T) {
	for _, test := range []struct {
		document string
		want     error
	}{
		{`{"schema_version":1,"candidates":[],"candidates":[]}`, ErrDuplicateCandidateDocumentKey},
		{`{"Schema_Version":1,"candidates":[]}`, ErrInvalidCandidateDocumentShape},
		{`{"schema_version":1,"candidates":null}`, ErrInvalidCandidateDocumentShape},
		{`{"schema_version":1,"candidates":[],"extra":true}`, ErrInvalidCandidateDocumentShape},
	} {
		if err := ValidateCandidateDocumentSyntax([]byte(test.document)); !errors.Is(err, test.want) {
			t.Fatalf("ValidateCandidateDocumentSyntax() = %v, want %v", err, test.want)
		}
	}
}

func TestParseCandidateBatchRejectsUnsupportedResponseEnvelope(t *testing.T) {
	response, snapshot, items := candidateFixture(t, validCandidateDocument())
	part := response.Parts()[0]
	lengthResponse, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishLength, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	if batch, err := ParseCandidateBatch(lengthResponse, snapshot, items); !errors.Is(err, ErrInvalidCandidateResponseEnvelope) || batch.Identity() != "" {
		t.Fatalf("length response = (%#v, %v)", batch, err)
	}
	text, _ := provider.NewResponsePart(provider.ResponsePartAssistantText, "text/plain", []byte("not structured"))
	textResponse, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{text}, provider.NewUnknownRouteTokenUsage())
	if batch, err := ParseCandidateBatch(textResponse, snapshot, items); !errors.Is(err, ErrInvalidCandidateResponseEnvelope) || batch.Identity() != "" {
		t.Fatalf("text response = (%#v, %v)", batch, err)
	}
	multiResponse, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part, part}, provider.NewUnknownRouteTokenUsage())
	if batch, err := ParseCandidateBatch(multiResponse, snapshot, items); !errors.Is(err, ErrInvalidCandidateResponseEnvelope) || batch.Identity() != "" {
		t.Fatalf("multi-part response = (%#v, %v)", batch, err)
	}
}

func TestParseCandidateBatchRejectsUnboundOrOutOfRangeEvidence(t *testing.T) {
	missing := strings.Replace(validCandidateDocument(), "evidence-1", "evidence-2", 1)
	response, snapshot, items := candidateFixture(t, missing)
	if batch, err := ParseCandidateBatch(response, snapshot, items); !errors.Is(err, ErrCandidateEvidenceNotAllowed) || batch.Identity() != "" {
		t.Fatalf("missing source = (%#v, %v)", batch, err)
	}
	outside := strings.Replace(validCandidateDocument(), `"start_line":12,"end_line":13`, `"start_line":21,"end_line":21`, 1)
	response, snapshot, items = candidateFixture(t, outside)
	if batch, err := ParseCandidateBatch(response, snapshot, items); !errors.Is(err, ErrCandidateRangeNotSupported) || batch.Identity() != "" {
		t.Fatalf("outside range = (%#v, %v)", batch, err)
	}
	otherRange, _ := evidence.NewSourceRange("internal/other.go", 1, 2)
	otherItem, _ := evidence.NewEvidenceItem("other-evidence", evidence.EvidenceKindSource, strings.Repeat("c", 64), otherRange)
	document := strings.Replace(validCandidateDocument(), `"evidence_ids":["evidence-1"]`, `"evidence_ids":["other-evidence"]`, 1)
	response, snapshot, items = candidateFixture(t, document)
	items = append(items, otherItem)
	if batch, err := ParseCandidateBatch(response, snapshot, items); !errors.Is(err, ErrCandidateEvidenceRangeMismatch) || batch.Identity() != "" {
		t.Fatalf("range mismatch = (%#v, %v)", batch, err)
	}
}

func TestParseCandidateBatchEnforcesSemanticBounds(t *testing.T) {
	var candidate map[string]any
	var root map[string]any
	if err := json.Unmarshal([]byte(validCandidateDocument()), &root); err != nil {
		t.Fatal(err)
	}
	candidate = root["candidates"].([]any)[0].(map[string]any)
	candidates := make([]any, maxCandidateFindings+1)
	for index := range candidates {
		candidates[index] = candidate
	}
	root["candidates"] = candidates
	encoded, _ := json.Marshal(root)
	if err := ValidateCandidateDocumentSyntax(encoded); !errors.Is(err, ErrTooManyCandidateFindings) {
		t.Fatalf("too many candidates = %v", err)
	}
	for _, test := range []struct {
		old, replacement string
		want             error
	}{
		{`"title":"Unchecked write error"`, `"title":""`, ErrInvalidCandidateText},
		{`"severity_hint":"high"`, `"severity_hint":"unknown"`, ErrInvalidCandidateSeverity},
		{`"evidence_ids":["evidence-1"]`, `"evidence_ids":["evidence-1","evidence-1"]`, ErrDuplicateCandidateEvidence},
		{`"source_id":"evidence-1"`, `"source_id":"bad/id"`, ErrInvalidCandidateReference},
	} {
		response, snapshot, items := candidateFixture(t, strings.Replace(validCandidateDocument(), test.old, test.replacement, 1))
		if batch, err := ParseCandidateBatch(response, snapshot, items); !errors.Is(err, test.want) || batch.Identity() != "" {
			t.Fatalf("invalid field = (%#v, %v), want %v", batch, err, test.want)
		}
	}
}

func TestCandidateBatchRejectsDuplicateAndForgedContent(t *testing.T) {
	var root map[string]any
	if err := json.Unmarshal([]byte(validCandidateDocument()), &root); err != nil {
		t.Fatal(err)
	}
	candidates := root["candidates"].([]any)
	root["candidates"] = append(candidates, candidates[0])
	encoded, _ := json.Marshal(root)
	response, snapshot, items := candidateFixture(t, string(encoded))
	if batch, err := ParseCandidateBatch(response, snapshot, items); !errors.Is(err, ErrDuplicateCandidateFinding) || batch.Identity() != "" {
		t.Fatalf("duplicate findings = (%#v, %v)", batch, err)
	}
	response, snapshot, items = candidateFixture(t, validCandidateDocument())
	batch, _ := ParseCandidateBatch(response, snapshot, items)
	forged := batch
	forged.identity = strings.Repeat("f", 64)
	if !errors.Is(forged.Validate(), ErrInvalidCandidateBatchIdentity) {
		t.Fatal("forged batch identity accepted")
	}
	changedResponse, _, _ := candidateFixture(t, strings.Replace(validCandidateDocument(), "discarded", "ignored", 1))
	changed, _ := ParseCandidateBatch(changedResponse, snapshot, items)
	if changed.Identity() == batch.Identity() || changed.Findings()[0].Identity() == batch.Findings()[0].Identity() {
		t.Fatal("candidate identity ignored content")
	}
}
