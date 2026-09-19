package artifact

import (
	"bytes"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

func TestPayloadSizeBytesIsStoredMetadataNotValidation(t *testing.T) {
	if (Artifact{}).PayloadSizeBytes() != 0 {
		t.Fatal("zero artifact length is not zero")
	}
	partial := Artifact{payload: []byte("invalid partial artifact")}
	if partial.Validate() == nil || partial.PayloadSizeBytes() != len("invalid partial artifact") {
		t.Fatal("metadata accessor validated or changed partial value")
	}
	scope, err := audit.NewReviewScope("tenant", "repo", "payload-length")
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1, 1024, 1 << 20} {
		payload := bytes.Repeat([]byte{'x'}, size)
		value, err := New(scope, KindTaskInput, "application/json", ClassificationConfidential, OriginHost, ProtectionProcessPrivate, []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, payload, time.UnixMilli(1000), time.UnixMilli(2000))
		if err != nil {
			t.Fatal(err)
		}
		if value.PayloadSizeBytes() != size || len(value.Payload()) != size {
			t.Fatal("stored valid payload length changed")
		}
		encoded, err := Encode(value)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := Parse(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Identity() != value.Identity() || parsed.PayloadSizeBytes() != size {
			t.Fatal("length accessor changed artifact encoding")
		}
	}
}
func TestPayloadSizeBytesRepeatedInspectionAllocatesNothing(t *testing.T) {
	value := Artifact{payload: bytes.Repeat([]byte{'x'}, 1<<20)}
	var size int
	allocations := testing.AllocsPerRun(1000, func() { size = value.PayloadSizeBytes() })
	if allocations != 0 || size != 1<<20 {
		t.Fatal("metadata-only length inspection copied or allocated payload")
	}
}
