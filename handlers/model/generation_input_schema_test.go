package model

import (
	"encoding/json"
	"fmt"
	"testing"

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
			var document struct {
				SchemaVersion int `json:"schema_version"`
			}
			if err := json.Unmarshal(encoded, &document); err != nil {
				t.Fatal(err)
			}
			if version := document.SchemaVersion; version != tc.version {
				t.Fatalf("encoded schema_version %v, want %d", version, tc.version)
			}
			for version := 1; version <= 4; version++ {
				id := fmt.Sprintf("urn:open-trestle:schema:artifact:model-generation-input:v%d", version)
				if !schemas.Has(id) {
					continue
				}
				err := schemas.Validate(id, encoded)
				if version == tc.version && err != nil {
					t.Fatalf("model-generation-input v%d schema refuses its encoding: %v", version, err)
				}
				if version != tc.version && err == nil {
					t.Fatalf("model-generation-input v%d schema admits a v%d encoding", version, tc.version)
				}
			}
			if !schemas.Has(fmt.Sprintf("urn:open-trestle:schema:artifact:model-generation-input:v%d", tc.version)) {
				t.Fatalf("model-generation-input v%d schema is not published", tc.version)
			}
		})
	}
}
