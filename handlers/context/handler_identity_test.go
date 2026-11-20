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

// The version 10 context (repository index stages, a per-packet source limit,
// the context manifest and the repository checks) alters the packet bytes this
// handler builds, so its identity moves to version 9, as the version 9 context
// moved it to version 8 and the earlier context changes moved it through
// versions 7 and 6. A plan that recorded an earlier identity is not served by
// this handler.
func TestContextAssemblyHandlerIdentityIsVersionNine(t *testing.T) {
	authorizer, sanitizer := strings.Repeat("5", 64), contextTestSanitizer{}.Identity()
	current := deriveHandlerIdentity(authorizer, sanitizer, review.ContextSpecialist{}, "", "", review.ContextBudget{})
	if current != contextAssemblyIdentityPreimage(t, 9, authorizer, sanitizer) {
		t.Fatal("route-granting context handler identity is not the version 9 preimage")
	}
	for _, earlier := range []int{5, 6, 7, 8} {
		if current == contextAssemblyIdentityPreimage(t, earlier, authorizer, sanitizer) {
			t.Fatalf("context handler identity did not change with its packet bytes (version %d)", earlier)
		}
	}
	specialist, err := review.NewContextSpecialist("bug_hunter")
	if err != nil {
		t.Fatal(err)
	}
	if bound := deriveHandlerIdentity(authorizer, sanitizer, specialist, "", "", review.ContextBudget{}); bound == current || bound == contextAssemblyIdentityPreimage(t, 5, authorizer, sanitizer) {
		t.Fatal("specialist handler identity collides with an unbound identity")
	}
	intent := strings.Repeat("6", 64)
	withIntent := deriveHandlerIdentity(authorizer, sanitizer, review.ContextSpecialist{}, intent, "", review.ContextBudget{})
	if withIntent == current || withIntent == deriveHandlerIdentity(authorizer, sanitizer, specialist, intent, "", review.ContextBudget{}) || withIntent == deriveHandlerIdentity(authorizer, sanitizer, review.ContextSpecialist{}, strings.Repeat("7", 64), "", review.ContextBudget{}) {
		t.Fatal("the change intent source is not bound into the handler identity")
	}
}

// The index source and the budget each change the packets a handler builds, so
// each is bound into the identity, and so is every field of the budget.
func TestContextAssemblyHandlerIdentityBindsIndexSourceAndBudget(t *testing.T) {
	authorizer, sanitizer := strings.Repeat("5", 64), contextTestSanitizer{}.Identity()
	derive := func(index string, budget review.ContextBudget) string {
		return deriveHandlerIdentity(authorizer, sanitizer, review.ContextSpecialist{}, "", index, budget)
	}
	unbound := derive("", review.ContextBudget{})
	budget := review.RouteContextBudget(64000, 4096)
	seen := map[string]string{"unbound": unbound}
	for name, identity := range map[string]string{
		"index source":       derive(strings.Repeat("8", 64), review.ContextBudget{}),
		"other index source": derive(strings.Repeat("9", 64), review.ContextBudget{}),
		"budget":             derive("", budget),
		"default budget":     derive("", review.DefaultContextBudget()),
		"source and budget":  derive(strings.Repeat("8", 64), budget),
		"other window":       derive("", review.RouteContextBudget(128000, 4096)),
		"other output":       derive("", review.RouteContextBudget(64000, 8192)),
	} {
		if previous, duplicate := seen[identity]; duplicate {
			t.Fatalf("%s handler identity equals the %s identity", name, previous)
		}
		seen[identity] = name
	}
}

// Context packets recorded by the earlier handlers (generation contexts 5, 7,
// 8 and 9) stay readable as recorded bytes but can no longer start a model
// attempt.
func TestRecordedEarlierPacketsAreReadbackOnly(t *testing.T) {
	for _, recorded := range []struct {
		path    string
		version int
		schema  string
	}{
		{"testdata/v5_packet_candidate_envelope.json", 5, review.ModelCandidateBatchV1SchemaIdentity},
		{"testdata/v7_packet_candidate_envelope.json", 7, review.ModelCandidateBatchSchemaIdentity},
		{"testdata/v8_packet_candidate_envelope.json", 8, review.ModelCandidateBatchSchemaIdentity},
		{"testdata/v9_packet_candidate_envelope.json", 9, review.ModelCandidateBatchSchemaIdentity},
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
