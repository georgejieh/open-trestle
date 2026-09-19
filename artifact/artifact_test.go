package artifact

import (
	"bytes"
	"github.com/georgejieh/open-trestle/audit"
	"strings"
	"testing"
	"time"
)

func TestNewArtifactBindsPayloadScopeRetentionAndProvenance(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	payload := []byte(`{"value":1}`)
	value, err := New(scope, KindContextPacket, "application/json", ClassificationConfidential, OriginHost, ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, payload, time.UnixMilli(100), time.UnixMilli(1000))
	if err != nil || value.Validate() != nil || value.Identity() == "" || value.PayloadDigest() == "" {
		t.Fatalf("artifact=(%#v,%v)", value, err)
	}
	copy := value.Payload()
	copy[0] = 'x'
	if bytes.Equal(copy, value.Payload()) {
		t.Fatal("payload was mutable")
	}
	encoded, err := Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(encoded)
	if err != nil || parsed.Identity() != value.Identity() || !bytes.Equal(parsed.Payload(), payload) || !bytes.Equal(encoded, mustEncode(t, parsed)) {
		t.Fatalf("parsed=(%#v,%v)", parsed, err)
	}
}
func mustEncode(t *testing.T, value Artifact) []byte {
	t.Helper()
	encoded, err := Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestAllArtifactKindsRoundTrip(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	kinds := []Kind{
		KindSourceSnapshot, KindChangeModel, KindDeterministicEvidence,
		KindRetrievalResult, KindContextPacket, KindCandidateBatch,
		KindVerificationBatch, KindVerifiedFindingSet, KindPublicationPlan,
		KindRunExport, KindTaskInput, KindWebhookDelivery, KindSourceFile, KindPublicationReceipt,
	}
	for _, kind := range kinds {
		value, err := New(
			scope, kind, "application/octet-stream", ClassificationConfidential,
			OriginHost, ProtectionProcessPrivate, []string{strings.Repeat("a", 64)},
			[]byte("payload"), time.UnixMilli(100), time.UnixMilli(1000),
		)
		if err != nil {
			t.Fatalf("kind %d: %v", kind, err)
		}
		encoded, err := Encode(value)
		if err != nil {
			t.Fatalf("encode %s: %v", kind, err)
		}
		parsed, err := Parse(encoded)
		if err != nil || parsed.Kind() != kind {
			t.Fatalf("parse %s = (%#v, %v)", kind, parsed, err)
		}
	}
}
