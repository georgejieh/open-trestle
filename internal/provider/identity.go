package provider

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

// Bounds transient identity hashing independently of request payload size.
const providerIdentityHashChunkBytes = 32 << 10

// Identity returns the versioned canonical identity of the complete request value.
func (r Request) Identity() string {
	if r.Validate() != nil {
		return ""
	}
	payloadDigest := sha256String(r.payload)
	preimage := struct {
		Contract         string `json:"contract"`
		SchemaVersion    int    `json:"schema_version"`
		Capability       string `json:"capability"`
		MediaTypeBase64  string `json:"media_type_base64"`
		PayloadDigest    string `json:"payload_digest"`
		PayloadSizeBytes int    `json:"payload_size_bytes"`
	}{
		Contract:         "open-trestle/provider-request",
		SchemaVersion:    1,
		Capability:       r.capability.String(),
		MediaTypeBase64:  base64.StdEncoding.EncodeToString([]byte(r.mediaType)),
		PayloadDigest:    hex.EncodeToString(payloadDigest[:]),
		PayloadSizeBytes: len(r.payload),
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func sha256String(value string) [sha256.Size]byte {
	hasher := sha256.New()
	var chunk [providerIdentityHashChunkBytes]byte
	for len(value) > 0 {
		copied := copy(chunk[:], value)
		_, _ = hasher.Write(chunk[:copied])
		value = value[copied:]
	}
	var digest [sha256.Size]byte
	hasher.Sum(digest[:0])
	return digest
}
