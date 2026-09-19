package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestOpaqueRequestIdentityRemainsVersionOne(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte("opaque probe"),
		{0xff, 0x00, 0xfe},
		[]byte(`{"output_schema_identity":"unknown","instructions":"caller-owned opaque data"}`),
	} {
		request, err := NewRequest(CapabilityReviewV1, "application/octet-stream", payload)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		preimage, err := json.Marshal(struct {
			Contract         string `json:"contract"`
			SchemaVersion    int    `json:"schema_version"`
			Capability       string `json:"capability"`
			MediaTypeBase64  string `json:"media_type_base64"`
			PayloadDigest    string `json:"payload_digest"`
			PayloadSizeBytes int    `json:"payload_size_bytes"`
		}{"open-trestle/provider-request", 1, "review.v1", base64.StdEncoding.EncodeToString([]byte("application/octet-stream")), hex.EncodeToString(digest[:]), len(payload)})
		if err != nil {
			t.Fatal(err)
		}
		identity := sha256.Sum256(preimage)
		if request.Identity() != hex.EncodeToString(identity[:]) || !bytes.Equal(request.Payload(), payload) {
			t.Fatal("opaque request changed identity or payload semantics")
		}
	}
}
