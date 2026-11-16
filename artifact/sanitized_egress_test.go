package artifact

import (
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

func TestSanitizedEgressArtifactKindsRoundTrip(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	for _, kind := range []Kind{KindSanitizedModelRequest, KindSanitizedEgressReceipt} {
		value, err := New(scope, kind, "application/json", ClassificationConfidential, OriginHost, ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, []byte(`{"value":1}`), time.UnixMilli(100), time.UnixMilli(1000))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := Encode(value)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := Parse(encoded)
		if err != nil || parsed.Kind() != kind {
			t.Fatalf("kind=%s parsed=(%#v,%v)", kind, parsed, err)
		}
	}
}
