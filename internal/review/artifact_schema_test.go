package review

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/schemacheck"
)

// recordedSchemaCase is one durable encoding with the version it must record.
type recordedSchemaCase struct {
	name    string
	version int
	encoded []byte
}

// requireRecordedSchemas validates each encoding against the published schema
// of its contract and version, and against the subschema that embeds it in a
// published result, so an encoder can never record what its schema refuses.
func requireRecordedSchemas(t *testing.T, contract string, embedding [2]string, cases []recordedSchemaCase) {
	t.Helper()
	schemas, err := schemacheck.Load("../../schemas")
	if err != nil {
		t.Fatal(err)
	}
	if !schemas.Has(embedding[0]) {
		t.Fatalf("result schema %s is not published", embedding[0])
	}
	embedded := embedding[0] + "#/properties/" + embedding[1]
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var document struct {
				SchemaVersion int `json:"schema_version"`
			}
			if err := json.Unmarshal(tc.encoded, &document); err != nil {
				t.Fatal(err)
			}
			if version := document.SchemaVersion; version != tc.version {
				t.Fatalf("encoded schema_version %v, want %d", version, tc.version)
			}
			if err := schemas.Validate(fmt.Sprintf("urn:open-trestle:schema:artifact:%s:v%d", contract, tc.version), tc.encoded); err != nil {
				t.Fatalf("%s v%d schema refuses its encoding: %v", contract, tc.version, err)
			}
			if err := schemas.Validate(embedded, tc.encoded); err != nil {
				t.Fatalf("%s refuses an embedded %s v%d: %v", embedding[0], contract, tc.version, err)
			}
			// No other version's schema admits it: a version 1 schema never
			// admits a side.
			for version := 1; version <= 3; version++ {
				id := fmt.Sprintf("urn:open-trestle:schema:artifact:%s:v%d", contract, version)
				if schemas.Has(id) && version != tc.version && schemas.Validate(id, tc.encoded) == nil {
					t.Fatalf("%s v%d schema admits a v%d encoding", contract, version, tc.version)
				}
			}
		})
	}
}

func mustEncode(t *testing.T, encode func() ([]byte, error)) []byte {
	t.Helper()
	encoded, err := encode()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestCandidateBatchEncodingsMatchTheirPublishedSchemas(t *testing.T) {
	_, _, _, _, _, headOnly := removedGuardCandidates(t, `["WINDOW"]`)
	_, _, _, _, removed, cited := removedGuardCandidates(t, `["WINDOW","REMOVED"]`)
	anchored := rederiveCandidate(cited, func(finding *CandidateFinding) {
		finding.sourceReferenceID, finding.side, finding.headLine = removed.ReferenceID(), LineSideBase, 3
		for _, binding := range finding.evidenceBindings {
			if binding.identity == removed.ReferenceID() {
				finding.sourceRange = binding.sourceRange
			}
		}
	})
	f, investigationRemoved := removedLinesInvestigationFixture(t, "\tif x == 0 { return 0 }\n")
	binding, err := NewInvestigationContextBinding(f.binding)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := NewInvestigationGenerationContext(binding, f.initial, f.initialSnapshot, InvestigationContextState{Turn: 1, ScannedBytes: uint64(len(f.changed.Content()))})
	if err != nil {
		t.Fatal(err)
	}
	investigation := func(source, cite string) CandidateBatch {
		document := `{"schema_version":1,"candidates":[{"title":"Missing guard","claim":"The zero check was removed.","severity_hint":"high","source_range":{"source_id":"` + source + `","start_line":1,"end_line":1},"evidence_ids":["` + cite + `"]}]}`
		batch, err := ParseInvestigationCandidateBatch(v7Response(t, document), initial)
		if err != nil {
			t.Fatal(err)
		}
		return batch
	}
	uncategorized := investigation(f.changed.ReferenceID(), f.changed.ReferenceID())
	sided := investigation(investigationRemoved.ReferenceID(), investigationRemoved.ReferenceID())
	requireRecordedSchemas(t, "candidate-batch", [2]string{"urn:open-trestle:schema:artifact:model-generation-result:v1", "candidate_batch"}, []recordedSchemaCase{
		{"uncategorized head", 1, mustEncode(t, func() ([]byte, error) { return EncodeCandidateBatch(uncategorized) })},
		{"categorized head", 2, mustEncode(t, func() ([]byte, error) { return EncodeCandidateBatch(headOnly) })},
		{"categorized citing base lines", 2, mustEncode(t, func() ([]byte, error) { return EncodeCandidateBatch(cited) })},
		{"categorized on base lines", 2, mustEncode(t, func() ([]byte, error) { return EncodeCandidateBatch(anchored) })},
		{"uncategorized on base lines", 3, mustEncode(t, func() ([]byte, error) { return EncodeCandidateBatch(sided) })},
	})
}

func TestVerificationBatchEncodingsMatchTheirPublishedSchemas(t *testing.T) {
	packet, snapshot, payload, window, removed, candidates := removedGuardCandidates(t, `["WINDOW","REMOVED"]`)
	request, err := NewVerificationRequestContext(payload, packet.Identity(), packet.ReviewScopeIdentity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), snapshot, packet.EvidenceItems(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	verdict := func(cited string) provider.Response {
		return v7Response(t, `{"schema_version":1,"verdicts":[{"candidate_id":"c1","outcome":"verified","severity":"high","rationale":"The removed guard leaves the division unchecked.","evidence_ids":`+cited+`}]}`)
	}
	headOnly, err := ParseContextVerificationBatch(verdict(`["`+window.ReferenceID()+`"]`), candidates, request)
	if err != nil {
		t.Fatal(err)
	}
	cited, err := ParseContextVerificationBatch(verdict(`["`+removed.ReferenceID()+`","`+window.ReferenceID()+`"]`), candidates, request)
	if err != nil {
		t.Fatal(err)
	}
	anchored := rederiveCandidate(candidates, func(finding *CandidateFinding) {
		finding.sourceReferenceID, finding.side = removed.ReferenceID(), LineSideBase
		for _, binding := range finding.evidenceBindings {
			if binding.identity == removed.ReferenceID() {
				finding.sourceRange = binding.sourceRange
			}
		}
	})
	anchoredRequest, err := NewVerificationRequestContext(payload, packet.Identity(), packet.ReviewScopeIdentity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), snapshot, packet.EvidenceItems(), anchored)
	if err != nil {
		t.Fatal(err)
	}
	onBase, err := ParseContextVerificationBatch(v7Response(t, `{"schema_version":1,"verdicts":[{"candidate_id":"c1","outcome":"verified","severity":"high","rationale":"The removed guard leaves the division unchecked.","evidence_ids":["`+removed.ReferenceID()+`"]}]}`), anchored, anchoredRequest)
	if err != nil {
		t.Fatal(err)
	}
	requireRecordedSchemas(t, "verification-batch", [2]string{"urn:open-trestle:schema:artifact:model-verification-result:v1", "verification_batch"}, []recordedSchemaCase{
		{"head", 1, mustEncode(t, func() ([]byte, error) { return EncodeVerificationBatch(headOnly) })},
		{"citing base lines", 2, mustEncode(t, func() ([]byte, error) { return EncodeVerificationBatch(cited) })},
		{"on base lines", 2, mustEncode(t, func() ([]byte, error) { return EncodeVerificationBatch(onBase) })},
	})
}

func TestVerifiedFindingSetEncodingsMatchTheirPublishedSchemas(t *testing.T) {
	_, headOnly := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	categorized := headOnly
	finding := headOnly.findings[0]
	finding.category = CandidateCategoryCorrectness
	finding.fingerprint = deriveVerifiedFindingFingerprint(finding)
	finding.identity = deriveVerifiedFindingIdentity(finding)
	categorized.findings = []VerifiedFinding{finding}
	categorized.identity = deriveVerifiedFindingSetIdentity(categorized)
	base := relabelBaseSide(t, headOnly)
	uncategorized := base
	finding = base.findings[0]
	finding.category, finding.headLine = "", 4
	finding.fingerprint = deriveVerifiedFindingFingerprint(finding)
	finding.identity = deriveVerifiedFindingIdentity(finding)
	uncategorized.findings = []VerifiedFinding{finding}
	uncategorized.identity = deriveVerifiedFindingSetIdentity(uncategorized)
	requireRecordedSchemas(t, "verified-finding-set", [2]string{"urn:open-trestle:schema:artifact:model-verification-result:v1", "verified_finding_set"}, []recordedSchemaCase{
		{"uncategorized head", 1, mustEncode(t, func() ([]byte, error) { return EncodeVerifiedFindingSet(headOnly) })},
		{"categorized head", 2, mustEncode(t, func() ([]byte, error) { return EncodeVerifiedFindingSet(categorized) })},
		{"categorized on base lines", 2, mustEncode(t, func() ([]byte, error) { return EncodeVerifiedFindingSet(base) })},
		{"uncategorized on base lines", 3, mustEncode(t, func() ([]byte, error) { return EncodeVerifiedFindingSet(uncategorized) })},
	})
}
