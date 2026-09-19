package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestRequestIdentityUsesCanonicalPreimage(t *testing.T) {
	payload := []byte("review payload")
	request, err := NewRequest(CapabilityReviewV1, " application/json ", payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	preimage := struct {
		Contract         string `json:"contract"`
		SchemaVersion    int    `json:"schema_version"`
		Capability       string `json:"capability"`
		MediaTypeBase64  string `json:"media_type_base64"`
		PayloadDigest    string `json:"payload_digest"`
		PayloadSizeBytes int    `json:"payload_size_bytes"`
	}{"open-trestle/provider-request", 1, "review.v1", base64.StdEncoding.EncodeToString([]byte("application/json")), hex.EncodeToString(digest[:]), len(payload)}
	encoded, _ := json.Marshal(preimage)
	identity := sha256.Sum256(encoded)
	want := hex.EncodeToString(identity[:])
	if request.Identity() != want || len(request.Identity()) != 64 || request.Identity() != strings.ToLower(request.Identity()) {
		t.Fatalf("Identity() = %q, want %q", request.Identity(), want)
	}
}

func TestRequestIdentityChangesWithEverySemanticField(t *testing.T) {
	first, _ := NewRequest(CapabilityReviewV1, "application/json", []byte("one"))
	media, _ := NewRequest(CapabilityReviewV1, "application/octet-stream", []byte("one"))
	payload, _ := NewRequest(CapabilityReviewV1, "application/json", []byte("two"))
	longer, _ := NewRequest(CapabilityReviewV1, "application/json", []byte("one\n"))
	identities := []string{first.Identity(), media.Identity(), payload.Identity(), longer.Identity()}
	for i := range identities {
		if identities[i] == "" {
			t.Fatalf("identity %d is empty", i)
		}
		for j := 0; j < i; j++ {
			if identities[i] == identities[j] {
				t.Fatalf("identities %d and %d match", i, j)
			}
		}
	}
}

func TestRequestIdentityIsStableAcrossCopiesAndPayloadAccess(t *testing.T) {
	request, _ := NewRequest(CapabilityReviewV1, "application/json", []byte("payload"))
	identity := request.Identity()
	copied := request
	returned := request.Payload()
	returned[0] = 'X'
	if request.Identity() != identity || copied.Identity() != identity || request.Payload()[0] != 'p' {
		t.Fatal("request identity changed through copy or accessor")
	}
}

func TestRequestIdentityPreservesNonUTF8MediaBytes(t *testing.T) {
	first, err := NewRequest(CapabilityReviewV1, "application/json; name=\"\xff\"", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewRequest(CapabilityReviewV1, "application/json; name=\"\xfe\"", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if first.MediaType() == second.MediaType() || first.Identity() == second.Identity() {
		t.Fatal("distinct media type bytes share an identity")
	}
}

func TestRequestIdentityAllocatedBytesDoNotScaleWithPayload(t *testing.T) {
	allocatedBytes := func(request Request) int64 {
		result := testing.Benchmark(func(b *testing.B) {
			var identity string
			for i := 0; i < b.N; i++ {
				identity = request.Identity()
			}
			if len(identity) != sha256.Size*2 {
				b.Fatal("invalid identity")
			}
		})
		return result.AllocedBytesPerOp()
	}
	small, _ := NewRequest(CapabilityReviewV1, "application/json", []byte("x"))
	large, _ := NewRequest(CapabilityReviewV1, "application/json", make([]byte, maxProviderRequestPayloadBytes))
	smallBytes := allocatedBytes(small)
	largeBytes := allocatedBytes(large)
	if largeBytes > smallBytes+1024 {
		t.Fatalf("allocated bytes scale with payload: small %d, large %d", smallBytes, largeBytes)
	}
}

func TestInvalidRequestHasNoIdentity(t *testing.T) {
	for _, request := range []Request{
		{},
		{capability: CapabilityReviewV1, mediaType: "application/json"},
		{capability: Capability(99), mediaType: "application/json", payload: "x"},
		{capability: CapabilityReviewV1, mediaType: "invalid media", payload: "x"},
	} {
		if request.Identity() != "" {
			t.Fatalf("invalid request identity = %q", request.Identity())
		}
	}
}
