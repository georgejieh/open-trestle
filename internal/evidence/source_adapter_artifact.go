package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// SourceAdapterArtifactKind identifies an opaque adapter artifact category.
type SourceAdapterArtifactKind string

const (
	SourceAdapterArtifactComponent SourceAdapterArtifactKind = "source_adapter_component"
	maxSourceAdapterArtifactBytes                            = 64 << 20
)

const sourceAdapterArtifactDigestAlgorithm = "sha256"

// SourceAdapterImplementationArtifact records exact bytes associated with an adapter identity.
type SourceAdapterImplementationArtifact struct {
	identity              string
	sourceAdapterIdentity string
	kind                  SourceAdapterArtifactKind
	digestAlgorithm       string
	digest                string
	sizeBytes             int
}

// NewSourceAdapterImplementationArtifact records bounded opaque component bytes without execution claims.
func NewSourceAdapterImplementationArtifact(adapter SourceAdapterIdentity, kind SourceAdapterArtifactKind, content []byte) (SourceAdapterImplementationArtifact, error) {
	canonicalAdapter, err := NewSourceAdapterIdentity(adapter.Kind(), adapter.Name(), adapter.Version(), adapter.Capabilities())
	if err != nil || !sourceAdapterIdentityValuesEqual(adapter, canonicalAdapter) {
		return SourceAdapterImplementationArtifact{}, fmt.Errorf("source adapter identity is not canonical")
	}
	if kind != SourceAdapterArtifactComponent {
		return SourceAdapterImplementationArtifact{}, fmt.Errorf("unsupported source adapter artifact kind %q", kind)
	}
	if len(content) == 0 || len(content) > maxSourceAdapterArtifactBytes {
		return SourceAdapterImplementationArtifact{}, fmt.Errorf("source adapter artifact has %d bytes, want 1 to %d", len(content), maxSourceAdapterArtifactBytes)
	}
	contentDigest := sha256.Sum256(content)
	digest := hex.EncodeToString(contentDigest[:])
	preimage := struct {
		Contract              string                    `json:"contract"`
		SchemaVersion         int                       `json:"schema_version"`
		SourceAdapterIdentity string                    `json:"source_adapter_identity"`
		Kind                  SourceAdapterArtifactKind `json:"kind"`
		DigestAlgorithm       string                    `json:"digest_algorithm"`
		Digest                string                    `json:"digest"`
		SizeBytes             int                       `json:"size_bytes"`
	}{
		Contract:              "open-trestle/source-adapter-implementation-artifact",
		SchemaVersion:         1,
		SourceAdapterIdentity: canonicalAdapter.Identity(),
		Kind:                  kind,
		DigestAlgorithm:       sourceAdapterArtifactDigestAlgorithm,
		Digest:                digest,
		SizeBytes:             len(content),
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return SourceAdapterImplementationArtifact{}, fmt.Errorf("encode source adapter implementation artifact identity: %w", err)
	}
	identityDigest := sha256.Sum256(encoded)
	return SourceAdapterImplementationArtifact{
		identity:              hex.EncodeToString(identityDigest[:]),
		sourceAdapterIdentity: canonicalAdapter.Identity(),
		kind:                  kind,
		digestAlgorithm:       sourceAdapterArtifactDigestAlgorithm,
		digest:                digest,
		sizeBytes:             len(content),
	}, nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (a SourceAdapterImplementationArtifact) Identity() string {
	return a.identity
}

// SourceAdapterIdentity returns the exact associated adapter identity.
func (a SourceAdapterImplementationArtifact) SourceAdapterIdentity() string {
	return a.sourceAdapterIdentity
}

// Kind returns the opaque artifact category.
func (a SourceAdapterImplementationArtifact) Kind() SourceAdapterArtifactKind {
	return a.kind
}

// DigestAlgorithm returns the exact content digest algorithm.
func (a SourceAdapterImplementationArtifact) DigestAlgorithm() string {
	return a.digestAlgorithm
}

// Digest returns the lowercase digest of the exact supplied bytes.
func (a SourceAdapterImplementationArtifact) Digest() string {
	return a.digest
}

// SizeBytes returns the exact supplied content size.
func (a SourceAdapterImplementationArtifact) SizeBytes() int {
	return a.sizeBytes
}
