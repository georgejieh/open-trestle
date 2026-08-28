package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// RepositoryAcquisitionArtifact identifies a requested read-only source artifact.
type RepositoryAcquisitionArtifact string

// RepositoryAcquisitionEffect identifies the permitted acquisition effect.
type RepositoryAcquisitionEffect string

const (
	AcquisitionArtifactManifest           RepositoryAcquisitionArtifact = "manifest"
	AcquisitionArtifactManifestAndContent RepositoryAcquisitionArtifact = "manifest_and_content"

	AcquisitionEffectReadOnly RepositoryAcquisitionEffect = "read_only"
)

// RepositoryAcquisitionRequest records canonical intent for one immutable revision.
type RepositoryAcquisitionRequest struct {
	identity              string
	repositoryIdentity    string
	revisionIdentity      string
	sourceAdapterIdentity string
	artifact              RepositoryAcquisitionArtifact
	effect                RepositoryAcquisitionEffect
	requiredCapabilities  []SourceAdapterCapability
}

// NewRepositoryAcquisitionRequest validates canonical read-only acquisition intent.
func NewRepositoryAcquisitionRequest(repository RepositoryIdentity, revision RevisionIdentity, adapter SourceAdapterIdentity, artifact RepositoryAcquisitionArtifact, effect RepositoryAcquisitionEffect) (RepositoryAcquisitionRequest, error) {
	canonicalRepository, err := NewRepositoryIdentity(repository.Authority(), repository.Namespace(), repository.Name())
	if err != nil || !repositoryIdentityValuesEqual(repository, canonicalRepository) {
		return RepositoryAcquisitionRequest{}, fmt.Errorf("repository identity is not canonical")
	}
	canonicalRevision, err := NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || revision != canonicalRevision {
		return RepositoryAcquisitionRequest{}, fmt.Errorf("revision identity is not canonical")
	}
	canonicalAdapter, err := NewSourceAdapterIdentity(adapter.Kind(), adapter.Name(), adapter.Version(), adapter.Capabilities())
	if err != nil || !sourceAdapterIdentityValuesEqual(adapter, canonicalAdapter) {
		return RepositoryAcquisitionRequest{}, fmt.Errorf("source adapter identity is not canonical")
	}
	requiredCapabilities, err := acquisitionCapabilities(artifact)
	if err != nil {
		return RepositoryAcquisitionRequest{}, err
	}
	if effect != AcquisitionEffectReadOnly {
		return RepositoryAcquisitionRequest{}, fmt.Errorf("unsupported repository acquisition effect %q", effect)
	}
	for _, capability := range requiredCapabilities {
		if !canonicalAdapter.HasCapability(capability) {
			return RepositoryAcquisitionRequest{}, fmt.Errorf("source adapter lacks required capability %q", capability)
		}
	}
	preimage := struct {
		Contract              string                        `json:"contract"`
		SchemaVersion         int                           `json:"schema_version"`
		RepositoryIdentity    string                        `json:"repository_identity"`
		RevisionIdentity      string                        `json:"revision_identity"`
		SourceAdapterIdentity string                        `json:"source_adapter_identity"`
		Artifact              RepositoryAcquisitionArtifact `json:"artifact"`
		Effect                RepositoryAcquisitionEffect   `json:"effect"`
		RequiredCapabilities  []SourceAdapterCapability     `json:"required_capabilities"`
	}{
		Contract:              "open-trestle/repository-acquisition-request",
		SchemaVersion:         1,
		RepositoryIdentity:    canonicalRepository.Identity(),
		RevisionIdentity:      canonicalRevision.Identity(),
		SourceAdapterIdentity: canonicalAdapter.Identity(),
		Artifact:              artifact,
		Effect:                effect,
		RequiredCapabilities:  requiredCapabilities,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryAcquisitionRequest{}, fmt.Errorf("encode repository acquisition request identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return RepositoryAcquisitionRequest{
		identity:              hex.EncodeToString(digest[:]),
		repositoryIdentity:    canonicalRepository.Identity(),
		revisionIdentity:      canonicalRevision.Identity(),
		sourceAdapterIdentity: canonicalAdapter.Identity(),
		artifact:              artifact,
		effect:                effect,
		requiredCapabilities:  append([]SourceAdapterCapability{}, requiredCapabilities...),
	}, nil
}

func acquisitionCapabilities(artifact RepositoryAcquisitionArtifact) ([]SourceAdapterCapability, error) {
	switch artifact {
	case AcquisitionArtifactManifest:
		return []SourceAdapterCapability{SourceCapabilityReadManifest}, nil
	case AcquisitionArtifactManifestAndContent:
		return []SourceAdapterCapability{SourceCapabilityReadContent, SourceCapabilityReadManifest}, nil
	default:
		return nil, fmt.Errorf("unsupported repository acquisition artifact %q", artifact)
	}
}

func repositoryIdentityValuesEqual(first, second RepositoryIdentity) bool {
	if (first.namespace == nil) != (second.namespace == nil) || first.identity != second.identity || first.authority != second.authority || first.name != second.name || len(first.namespace) != len(second.namespace) {
		return false
	}
	for i := range first.namespace {
		if first.namespace[i] != second.namespace[i] {
			return false
		}
	}
	return true
}

func sourceAdapterIdentityValuesEqual(first, second SourceAdapterIdentity) bool {
	if (first.capabilities == nil) != (second.capabilities == nil) || first.identity != second.identity || first.kind != second.kind || first.name != second.name || first.version != second.version || first.majorVersion != second.majorVersion || len(first.capabilities) != len(second.capabilities) {
		return false
	}
	for i := range first.capabilities {
		if first.capabilities[i] != second.capabilities[i] {
			return false
		}
	}
	return true
}

// Identity returns the versioned canonical SHA-256 identity.
func (r RepositoryAcquisitionRequest) Identity() string {
	return r.identity
}

// RepositoryIdentity returns the exact requested repository identity.
func (r RepositoryAcquisitionRequest) RepositoryIdentity() string {
	return r.repositoryIdentity
}

// RevisionIdentity returns the exact requested revision identity.
func (r RepositoryAcquisitionRequest) RevisionIdentity() string {
	return r.revisionIdentity
}

// SourceAdapterIdentity returns the exact requested source adapter identity.
func (r RepositoryAcquisitionRequest) SourceAdapterIdentity() string {
	return r.sourceAdapterIdentity
}

// Artifact returns the requested read-only artifact mode.
func (r RepositoryAcquisitionRequest) Artifact() RepositoryAcquisitionArtifact {
	return r.artifact
}

// Effect returns the permitted acquisition effect.
func (r RepositoryAcquisitionRequest) Effect() RepositoryAcquisitionEffect {
	return r.effect
}

// RequiredCapabilities returns the mechanically derived capability requirements.
func (r RepositoryAcquisitionRequest) RequiredCapabilities() []SourceAdapterCapability {
	return append([]SourceAdapterCapability{}, r.requiredCapabilities...)
}
