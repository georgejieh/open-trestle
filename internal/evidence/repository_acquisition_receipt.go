package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// RepositoryAcquisitionOutcome identifies a terminal acquisition attempt state.
type RepositoryAcquisitionOutcome string

// RepositoryContentCoverage identifies exact requested content coverage.
type RepositoryContentCoverage string

// RepositoryAcquisitionReason identifies a typed terminal-state reason.
type RepositoryAcquisitionReason string

const (
	AcquisitionOutcomeAcquired RepositoryAcquisitionOutcome = "acquired"
	AcquisitionOutcomeBlocked  RepositoryAcquisitionOutcome = "blocked"
	AcquisitionOutcomeFailed   RepositoryAcquisitionOutcome = "failed"

	ContentCoverageNotRequested RepositoryContentCoverage = "not_requested"
	ContentCoverageComplete     RepositoryContentCoverage = "complete"
	ContentCoverageUnavailable  RepositoryContentCoverage = "unavailable"

	AcquisitionReasonNone                  RepositoryAcquisitionReason = "none"
	AcquisitionReasonCapabilityUnavailable RepositoryAcquisitionReason = "capability_unavailable"
	AcquisitionReasonAuthorizationRequired RepositoryAcquisitionReason = "authorization_required"
	AcquisitionReasonPolicyBlocked         RepositoryAcquisitionReason = "policy_blocked"
	AcquisitionReasonAdapterUnavailable    RepositoryAcquisitionReason = "adapter_unavailable"
	AcquisitionReasonAdapterFailure        RepositoryAcquisitionReason = "adapter_failure"
	AcquisitionReasonArtifactIncomplete    RepositoryAcquisitionReason = "artifact_incomplete"
	AcquisitionReasonResourceLimit         RepositoryAcquisitionReason = "resource_limit"
)

// RepositoryAcquisitionReceipt records a canonical claimed terminal acquisition result.
type RepositoryAcquisitionReceipt struct {
	identity              string
	requestIdentity       string
	repositoryIdentity    string
	revisionIdentity      string
	sourceAdapterIdentity string
	artifact              RepositoryAcquisitionArtifact
	effect                RepositoryAcquisitionEffect
	outcome               RepositoryAcquisitionOutcome
	reason                RepositoryAcquisitionReason
	manifestIdentity      string
	contentCoverage       RepositoryContentCoverage
}

// NewRepositoryAcquisitionReceipt validates a claimed result and exact supplied content coverage.
func NewRepositoryAcquisitionReceipt(request RepositoryAcquisitionRequest, outcome RepositoryAcquisitionOutcome, reason RepositoryAcquisitionReason, manifest RepositoryManifest, contents map[string][]byte) (RepositoryAcquisitionReceipt, error) {
	canonicalRequest, err := canonicalRepositoryAcquisitionRequest(request)
	if err != nil {
		return RepositoryAcquisitionReceipt{}, err
	}
	if err := validateAcquisitionOutcomeReason(outcome, reason); err != nil {
		return RepositoryAcquisitionReceipt{}, err
	}
	manifestIdentity := ""
	var coverage RepositoryContentCoverage
	if outcome == AcquisitionOutcomeAcquired {
		canonicalManifest, err := NewRepositoryManifest(manifest.Files())
		if err != nil || !repositoryManifestValuesEqual(manifest, canonicalManifest) {
			return RepositoryAcquisitionReceipt{}, fmt.Errorf("repository manifest is not canonical")
		}
		manifestIdentity = canonicalManifest.Identity()
		switch canonicalRequest.Artifact() {
		case AcquisitionArtifactManifest:
			if len(contents) != 0 {
				return RepositoryAcquisitionReceipt{}, fmt.Errorf("manifest acquisition must not include content")
			}
			coverage = ContentCoverageNotRequested
		case AcquisitionArtifactManifestAndContent:
			if err := validateAcquisitionContents(canonicalManifest, contents); err != nil {
				return RepositoryAcquisitionReceipt{}, err
			}
			coverage = ContentCoverageComplete
		default:
			return RepositoryAcquisitionReceipt{}, fmt.Errorf("unsupported repository acquisition artifact %q", canonicalRequest.Artifact())
		}
	} else {
		if !isZeroRepositoryManifest(manifest) {
			return RepositoryAcquisitionReceipt{}, fmt.Errorf("non-acquired result must not include a manifest")
		}
		if len(contents) != 0 {
			return RepositoryAcquisitionReceipt{}, fmt.Errorf("non-acquired result must not include content")
		}
		switch canonicalRequest.Artifact() {
		case AcquisitionArtifactManifest:
			coverage = ContentCoverageNotRequested
		case AcquisitionArtifactManifestAndContent:
			coverage = ContentCoverageUnavailable
		default:
			return RepositoryAcquisitionReceipt{}, fmt.Errorf("unsupported repository acquisition artifact %q", canonicalRequest.Artifact())
		}
	}
	preimage := struct {
		Contract              string                        `json:"contract"`
		SchemaVersion         int                           `json:"schema_version"`
		RequestIdentity       string                        `json:"request_identity"`
		RepositoryIdentity    string                        `json:"repository_identity"`
		RevisionIdentity      string                        `json:"revision_identity"`
		SourceAdapterIdentity string                        `json:"source_adapter_identity"`
		Artifact              RepositoryAcquisitionArtifact `json:"artifact"`
		Effect                RepositoryAcquisitionEffect   `json:"effect"`
		Outcome               RepositoryAcquisitionOutcome  `json:"outcome"`
		Reason                RepositoryAcquisitionReason   `json:"reason"`
		ManifestIdentity      string                        `json:"manifest_identity"`
		ContentCoverage       RepositoryContentCoverage     `json:"content_coverage"`
	}{
		Contract:              "open-trestle/repository-acquisition-receipt",
		SchemaVersion:         1,
		RequestIdentity:       canonicalRequest.Identity(),
		RepositoryIdentity:    canonicalRequest.RepositoryIdentity(),
		RevisionIdentity:      canonicalRequest.RevisionIdentity(),
		SourceAdapterIdentity: canonicalRequest.SourceAdapterIdentity(),
		Artifact:              canonicalRequest.Artifact(),
		Effect:                canonicalRequest.Effect(),
		Outcome:               outcome,
		Reason:                reason,
		ManifestIdentity:      manifestIdentity,
		ContentCoverage:       coverage,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryAcquisitionReceipt{}, fmt.Errorf("encode repository acquisition receipt identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return RepositoryAcquisitionReceipt{
		identity:              hex.EncodeToString(digest[:]),
		requestIdentity:       canonicalRequest.Identity(),
		repositoryIdentity:    canonicalRequest.RepositoryIdentity(),
		revisionIdentity:      canonicalRequest.RevisionIdentity(),
		sourceAdapterIdentity: canonicalRequest.SourceAdapterIdentity(),
		artifact:              canonicalRequest.Artifact(),
		effect:                canonicalRequest.Effect(),
		outcome:               outcome,
		reason:                reason,
		manifestIdentity:      manifestIdentity,
		contentCoverage:       coverage,
	}, nil
}

func validateAcquisitionOutcomeReason(outcome RepositoryAcquisitionOutcome, reason RepositoryAcquisitionReason) error {
	switch outcome {
	case AcquisitionOutcomeAcquired:
		if reason != AcquisitionReasonNone {
			return fmt.Errorf("acquired result requires reason %q", AcquisitionReasonNone)
		}
	case AcquisitionOutcomeBlocked:
		switch reason {
		case AcquisitionReasonCapabilityUnavailable, AcquisitionReasonAuthorizationRequired, AcquisitionReasonPolicyBlocked, AcquisitionReasonAdapterUnavailable:
		default:
			return fmt.Errorf("unsupported blocked acquisition reason %q", reason)
		}
	case AcquisitionOutcomeFailed:
		switch reason {
		case AcquisitionReasonAdapterFailure, AcquisitionReasonArtifactIncomplete, AcquisitionReasonResourceLimit:
		default:
			return fmt.Errorf("unsupported failed acquisition reason %q", reason)
		}
	default:
		return fmt.Errorf("unsupported repository acquisition outcome %q", outcome)
	}
	return nil
}

func validateAcquisitionContents(manifest RepositoryManifest, contents map[string][]byte) error {
	files := manifest.Files()
	if len(contents) != len(files) {
		return fmt.Errorf("acquired content has %d entries, want %d", len(contents), len(files))
	}
	for _, file := range files {
		if _, ok := contents[file.Path()]; !ok {
			return fmt.Errorf("acquired content does not contain path %q", file.Path())
		}
	}
	for _, file := range files {
		exactFile, err := NewRepositoryFile(file.Path(), contents[file.Path()])
		if err != nil || exactFile != file {
			return fmt.Errorf("acquired content does not match repository file %q", file.Path())
		}
	}
	return nil
}

func repositoryManifestValuesEqual(first, second RepositoryManifest) bool {
	if (first.files == nil) != (second.files == nil) || first.identity != second.identity || first.totalSizeBytes != second.totalSizeBytes || len(first.files) != len(second.files) {
		return false
	}
	for i := range first.files {
		if first.files[i] != second.files[i] {
			return false
		}
	}
	return true
}

func isZeroRepositoryManifest(manifest RepositoryManifest) bool {
	return manifest.identity == "" && manifest.files == nil && manifest.totalSizeBytes == 0
}

// Identity returns the versioned canonical SHA-256 identity.
func (r RepositoryAcquisitionReceipt) Identity() string {
	return r.identity
}

// RequestIdentity returns the exact acquisition request identity.
func (r RepositoryAcquisitionReceipt) RequestIdentity() string {
	return r.requestIdentity
}

// RepositoryIdentity returns the exact requested repository identity.
func (r RepositoryAcquisitionReceipt) RepositoryIdentity() string {
	return r.repositoryIdentity
}

// RevisionIdentity returns the exact requested revision identity.
func (r RepositoryAcquisitionReceipt) RevisionIdentity() string {
	return r.revisionIdentity
}

// SourceAdapterIdentity returns the exact requested source adapter identity.
func (r RepositoryAcquisitionReceipt) SourceAdapterIdentity() string {
	return r.sourceAdapterIdentity
}

// Artifact returns the requested artifact mode.
func (r RepositoryAcquisitionReceipt) Artifact() RepositoryAcquisitionArtifact {
	return r.artifact
}

// Effect returns the permitted acquisition effect.
func (r RepositoryAcquisitionReceipt) Effect() RepositoryAcquisitionEffect {
	return r.effect
}

// Outcome returns the terminal acquisition state.
func (r RepositoryAcquisitionReceipt) Outcome() RepositoryAcquisitionOutcome {
	return r.outcome
}

// Reason returns the typed terminal-state reason.
func (r RepositoryAcquisitionReceipt) Reason() RepositoryAcquisitionReason {
	return r.reason
}

// WasAttempted reports whether the outcome records an attempted execution.
func (r RepositoryAcquisitionReceipt) WasAttempted() bool {
	return r.outcome == AcquisitionOutcomeAcquired || r.outcome == AcquisitionOutcomeFailed
}

// HasManifest reports whether the receipt binds a canonical manifest.
func (r RepositoryAcquisitionReceipt) HasManifest() bool {
	return r.manifestIdentity != ""
}

// ManifestIdentity returns the acquired manifest identity, if present.
func (r RepositoryAcquisitionReceipt) ManifestIdentity() string {
	return r.manifestIdentity
}

// ContentCoverage returns exact content coverage relative to the manifest.
func (r RepositoryAcquisitionReceipt) ContentCoverage() RepositoryContentCoverage {
	return r.contentCoverage
}
