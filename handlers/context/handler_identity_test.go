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

// The version 8 context (removed_lines sources and their contract sentence)
// alters the packet bytes this handler builds, so its identity moves to
// version 7, as the text-fallback, instruction-file, and version 7 context
// changes moved it to version 6. A plan that recorded an earlier identity is
// not served by this handler.
func TestContextAssemblyHandlerIdentityIsVersionSeven(t *testing.T) {
	authorizer, sanitizer := strings.Repeat("5", 64), contextTestSanitizer{}.Identity()
	current := deriveHandlerIdentity(authorizer, sanitizer, review.ContextSpecialist{})
	if current != contextAssemblyIdentityPreimage(t, 7, authorizer, sanitizer) {
		t.Fatal("route-granting context handler identity is not the version 7 preimage")
	}
	if current == contextAssemblyIdentityPreimage(t, 6, authorizer, sanitizer) || current == contextAssemblyIdentityPreimage(t, 5, authorizer, sanitizer) {
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

// Context packets recorded by the version 5 and version 6 handlers (generation
// contexts 5 and 7) stay readable as recorded bytes but can no longer start a
// model attempt.
func TestRecordedEarlierPacketsAreReadbackOnly(t *testing.T) {
	for _, recorded := range []struct {
		path    string
		version int
		schema  string
	}{
		{"testdata/v5_packet_candidate_envelope.json", 5, review.ModelCandidateBatchV1SchemaIdentity},
		{"testdata/v7_packet_candidate_envelope.json", 7, review.ModelCandidateBatchSchemaIdentity},
	} {
		encoded, err := os.ReadFile(recorded.path)
		if err != nil {
			t.Fatal(err)
		}
		value, err := artifact.Parse(encoded)
		if err != nil || value.Kind() != artifact.KindContextPacket {
			t.Fatalf("recorded v%d envelope unreadable: %v", recorded.version, err)
		}
		var header struct {
			SchemaVersion        int    `json:"schema_version"`
			OutputSchemaIdentity string `json:"output_schema_identity"`
			ReviewScopeIdentity  string `json:"review_scope_identity"`
		}
		if err := json.Unmarshal(value.Payload(), &header); err != nil || header.SchemaVersion != recorded.version || header.OutputSchemaIdentity != recorded.schema {
			t.Fatalf("fixture is not a recorded v%d context", recorded.version)
		}
		if _, bound, err := review.RecordedContextSpecialist(value.Payload()); err != nil || bound {
			t.Fatalf("recorded v%d output contract rejected for readback: %v", recorded.version, err)
		}
		request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", value.Payload())
		if err != nil {
			t.Fatal(err)
		}
		if review.ValidateCandidateModelRequest(request, header.ReviewScopeIdentity) == nil {
			t.Fatalf("recorded v%d context admitted for a new model attempt", recorded.version)
		}
		if _, err := review.TrustedModelRequestInstructions(value.Payload()); err == nil {
			t.Fatalf("recorded v%d context produced trusted egress instructions", recorded.version)
		}
	}
}
