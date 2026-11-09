package model

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/schemacheck"
)

// Every generation input encoding validates against the published schema of
// its version, and no other version's schema admits it: version 1 never
// admits removed_lines evidence or an empty snapshot.
func TestGenerationInputEncodingsMatchTheirPublishedSchemas(t *testing.T) {
	schemas, err := schemacheck.Load("../../schemas")
	if err != nil {
		t.Fatal(err)
	}
	headScope, headSnapshot, headPacket, headArtifact, headRequest := generationContextFixture(t)
	head, err := NewGenerationInput(headArtifact, headPacket, headSnapshot, generationAuthorization(t, headScope, headRequest))
	if err != nil {
		t.Fatal(err)
	}
	secret := "sk-proj-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	scope, snapshot, packet, contextArtifact, raw := generationContextFixtureWithContent(t, []byte(secret+"\nline two\n"))
	sanitized, _, requestArtifact, receiptArtifact, expected := sanitizedGenerationFixture(t, scope, contextArtifact, raw, secret)
	dispatchRequest, err := sanitized.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	sanitizedInput, err := NewSanitizedGenerationInput(contextArtifact, packet, snapshot, requestArtifact, receiptArtifact, expected, generationAuthorization(t, scope, dispatchRequest))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		version int
		input   GenerationInput
	}{
		{"head evidence", 1, head},
		{"sanitized head evidence", 3, sanitizedInput},
		{"removed_lines evidence", 4, baseEvidenceGenerationInput(t, false)},
		{"removed file only", 4, baseEvidenceGenerationInput(t, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodeGenerationInput(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			requireGenerationInputSchema(t, schemas, encoded, tc.version)
		})
	}
}

// generationInputSchemaVersions are the published versions of the
// model-generation-input contract: 1, 3 and 4 for generation inputs, and 2 and
// 5 for investigation inputs.
const generationInputSchemaVersions = 5

// requireGenerationInputSchema checks that an encoded model-generation-input
// records the wanted version, that the schema of that version admits it, and
// that no other version's schema does.
func requireGenerationInputSchema(t *testing.T, schemas *schemacheck.Registry, encoded []byte, want int) {
	t.Helper()
	var document struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != want {
		t.Fatalf("encoded schema_version %v, want %d", document.SchemaVersion, want)
	}
	if !schemas.Has(fmt.Sprintf("urn:open-trestle:schema:artifact:model-generation-input:v%d", want)) {
		t.Fatalf("model-generation-input v%d schema is not published", want)
	}
	for version := 1; version <= generationInputSchemaVersions; version++ {
		id := fmt.Sprintf("urn:open-trestle:schema:artifact:model-generation-input:v%d", version)
		if !schemas.Has(id) {
			continue
		}
		err := schemas.Validate(id, encoded)
		if version == want && err != nil {
			t.Fatalf("model-generation-input v%d schema refuses its encoding: %v", version, err)
		}
		if version != want && err == nil {
			t.Fatalf("model-generation-input v%d schema admits a v%d encoding", version, want)
		}
	}
}

// Every investigation input encoding validates against the published schema
// of its version, and no other version's schema admits it: version 2 never
// admits removed_lines evidence or an empty snapshot. No published result
// schema embeds an investigation input.
func TestInvestigationInputEncodingsMatchTheirPublishedSchemas(t *testing.T) {
	schemas, err := schemacheck.Load("../../schemas")
	if err != nil {
		t.Fatal(err)
	}
	f := newArtifactsFixture(t)
	request, err := f.context.Context.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewInvestigationGenerationInputArtifact(f.context, f.predicted(t, request), f.expected, f.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	head, err := ParseInvestigationGenerationInput(input.Payload())
	if err != nil {
		t.Fatal(err)
	}
	rehash := func(claims InvestigationGenerationInput) InvestigationGenerationInput {
		values, err := claims.values()
		if err != nil {
			t.Fatal(err)
		}
		delete(values, "identity")
		encoded, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		claims.identity = artifactPayloadHash(encoded)
		return claims
	}
	removed := head
	removed.baseEvidence = map[string]struct{}{head.evidence[0].ID(): {}}
	removed = rehash(removed)
	removedOnly := removed
	removedOnly.snapshot, err = review.NewReviewSnapshot(head.snapshot.Workspace(), head.snapshot.Revision(), nil)
	if err != nil {
		t.Fatal(err)
	}
	removedOnly.baseEvidence = map[string]struct{}{}
	for _, item := range head.evidence {
		removedOnly.baseEvidence[item.ID()] = struct{}{}
	}
	removedOnly = rehash(removedOnly)
	for _, tc := range []struct {
		name    string
		version int
		input   InvestigationGenerationInput
	}{
		{"head evidence", 2, head},
		{"removed_lines evidence", 5, removed},
		{"removed file only", 5, removedOnly},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := EncodeInvestigationGenerationInput(tc.input)
			if err != nil {
				t.Fatal(err)
			}
			requireGenerationInputSchema(t, schemas, encoded, tc.version)
		})
	}
}
