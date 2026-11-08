package context

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

func contextAssemblyIdentityPreimage(t *testing.T, version int, authorizer, sanitizer string) string {
	t.Helper()
	encoded, err := json.Marshal(struct {
		Contract   string `json:"contract"`
		Version    int    `json:"version"`
		Authorizer string `json:"authorizer"`
		Sanitizer  string `json:"sanitizer,omitempty"`
	}{"open-trestle/context-assembly-handler", version, authorizer, sanitizer})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// The text-fallback, instruction-file, and version 7 context changes alter the
// packet bytes this handler builds, so its identity moves to version 6. A plan
// that recorded the version 5 identity is not served by this handler.
func TestContextAssemblyHandlerIdentityIsVersionSix(t *testing.T) {
	authorizer, sanitizer := strings.Repeat("5", 64), contextTestSanitizer{}.Identity()
	current := deriveHandlerIdentity(authorizer, sanitizer, review.ContextSpecialist{})
	if current != contextAssemblyIdentityPreimage(t, 6, authorizer, sanitizer) {
		t.Fatal("route-granting context handler identity is not the version 6 preimage")
	}
	if current == contextAssemblyIdentityPreimage(t, 5, authorizer, sanitizer) {
		t.Fatal("context handler identity did not change with its packet bytes")
	}
	specialist, err := review.NewContextSpecialist("bug_hunter")
	if err != nil {
		t.Fatal(err)
	}
	if bound := deriveHandlerIdentity(authorizer, sanitizer, specialist); bound == current || bound == contextAssemblyIdentityPreimage(t, 5, authorizer, sanitizer) {
		t.Fatal("specialist handler identity collides with an unbound identity")
	}
}

// A context packet recorded by the version 5 handler stays readable as recorded
// bytes but can no longer start a model attempt.
func TestRecordedVersionFivePacketIsReadbackOnly(t *testing.T) {
	encoded, err := os.ReadFile("testdata/v5_packet_candidate_envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	value, err := artifact.Parse(encoded)
	if err != nil || value.Kind() != artifact.KindContextPacket {
		t.Fatalf("recorded v5 envelope unreadable: %v", err)
	}
	var header struct {
		SchemaVersion        int    `json:"schema_version"`
		OutputSchemaIdentity string `json:"output_schema_identity"`
		ReviewScopeIdentity  string `json:"review_scope_identity"`
	}
	if err := json.Unmarshal(value.Payload(), &header); err != nil || header.SchemaVersion != 5 || header.OutputSchemaIdentity != review.ModelCandidateBatchV1SchemaIdentity {
		t.Fatal("fixture is not a recorded v5 context requesting candidate batch v1")
	}
	if _, bound, err := review.RecordedContextSpecialist(value.Payload()); err != nil || bound {
		t.Fatalf("recorded v5 output contract rejected for readback: %v", err)
	}
	request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", value.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if review.ValidateCandidateModelRequest(request, header.ReviewScopeIdentity) == nil {
		t.Fatal("recorded v5 context admitted for a new model attempt")
	}
	if _, err := review.TrustedModelRequestInstructions(value.Payload()); err == nil {
		t.Fatal("recorded v5 context produced trusted egress instructions")
	}
}
