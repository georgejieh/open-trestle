package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/analysis"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

// RepositoryAcquisitionProfileExecution binds one acquisition to deterministic repository profiling.
type RepositoryAcquisitionProfileExecution struct {
	identity      string
	acquisition   RepositoryAcquisitionExecution
	hasProfile    bool
	profileBundle analysis.RepositoryProfileBundle
}

// Identity returns the versioned canonical SHA-256 identity.
func (e RepositoryAcquisitionProfileExecution) Identity() string { return e.identity }

// Acquisition returns the exact runtime-owned acquisition execution.
func (e RepositoryAcquisitionProfileExecution) Acquisition() RepositoryAcquisitionExecution {
	return e.acquisition
}

// HasProfile reports whether an acquired result produced a complete profile bundle.
func (e RepositoryAcquisitionProfileExecution) HasProfile() bool { return e.hasProfile }

// ProfileBundle returns the deterministic profile bundle, if present.
func (e RepositoryAcquisitionProfileExecution) ProfileBundle() analysis.RepositoryProfileBundle {
	return e.profileBundle
}

// ExecuteRepositoryAcquisitionWithProfile profiles the exact content used for one receipt.
// Profiling is synchronous and returns no repository bytes.
func ExecuteRepositoryAcquisitionWithProfile(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter SourceAdapter) (RepositoryAcquisitionProfileExecution, error) {
	if isNilInterface(ctx) {
		return RepositoryAcquisitionProfileExecution{}, fmt.Errorf("repository acquisition context is nil")
	}
	if isNilInterface(adapter) {
		return RepositoryAcquisitionProfileExecution{}, fmt.Errorf("source adapter is nil")
	}
	if err := evidence.ValidateRepositoryAcquisitionRequest(request); err != nil {
		return RepositoryAcquisitionProfileExecution{}, err
	}
	if err := ctx.Err(); err != nil {
		return RepositoryAcquisitionProfileExecution{}, err
	}
	if request.Artifact() != evidence.AcquisitionArtifactManifestAndContent {
		return RepositoryAcquisitionProfileExecution{}, fmt.Errorf("repository profiling requires manifest and content acquisition")
	}
	runtime, err := executeRepositoryAcquisitionWithRetention(ctx, request, adapter, repositoryAcquisitionRetainResult)
	if err != nil {
		return RepositoryAcquisitionProfileExecution{}, err
	}
	if err := ctx.Err(); err != nil {
		return RepositoryAcquisitionProfileExecution{}, err
	}
	var bundle analysis.RepositoryProfileBundle
	hasProfile := false
	if runtime.execution.Outcome() == evidence.AcquisitionOutcomeAcquired {
		bundle, err = buildRepositoryAcquisitionProfile(ctx, runtime)
		if err != nil {
			return RepositoryAcquisitionProfileExecution{}, err
		}
		hasProfile = true
	}
	profiled, err := newRepositoryAcquisitionProfileExecution(runtime.execution, bundle, hasProfile)
	if err != nil {
		return RepositoryAcquisitionProfileExecution{}, err
	}
	if err := ctx.Err(); err != nil {
		return RepositoryAcquisitionProfileExecution{}, err
	}
	return profiled, nil
}

func buildRepositoryAcquisitionProfile(ctx context.Context, runtime repositoryAcquisitionRuntimeResult) (analysis.RepositoryProfileBundle, error) {
	if err := ctx.Err(); err != nil {
		return analysis.RepositoryProfileBundle{}, err
	}
	if runtime.execution.Outcome() != evidence.AcquisitionOutcomeAcquired || runtime.execution.Receipt().ContentCoverage() != evidence.ContentCoverageComplete || runtime.result.Outcome != evidence.AcquisitionOutcomeAcquired || runtime.result.Reason != evidence.AcquisitionReasonNone || runtime.result.Manifest.Identity() != runtime.execution.Receipt().ManifestIdentity() || runtime.result.Contents == nil {
		return analysis.RepositoryProfileBundle{}, fmt.Errorf("repository acquisition execution is not eligible for profiling")
	}
	profile, err := analysis.NewRepositoryProfile(runtime.result.Manifest)
	if err != nil {
		return analysis.RepositoryProfileBundle{}, err
	}
	if err := ctx.Err(); err != nil {
		return analysis.RepositoryProfileBundle{}, err
	}
	classification, err := analysis.ClassifyRepositoryManifest(runtime.result.Manifest, runtime.result.Contents)
	if err != nil {
		return analysis.RepositoryProfileBundle{}, err
	}
	if err := ctx.Err(); err != nil {
		return analysis.RepositoryProfileBundle{}, err
	}
	summary, err := analysis.NewRepositoryClassificationSummary(runtime.result.Manifest, classification)
	if err != nil {
		return analysis.RepositoryProfileBundle{}, err
	}
	if err := ctx.Err(); err != nil {
		return analysis.RepositoryProfileBundle{}, err
	}
	bundle, err := analysis.NewRepositoryProfileBundle(runtime.result.Manifest, profile, classification, summary)
	if err != nil {
		return analysis.RepositoryProfileBundle{}, err
	}
	if bundle.ManifestIdentity() != runtime.execution.Receipt().ManifestIdentity() {
		return analysis.RepositoryProfileBundle{}, fmt.Errorf("repository profile bundle does not match acquisition execution")
	}
	if err := ctx.Err(); err != nil {
		return analysis.RepositoryProfileBundle{}, err
	}
	return bundle, nil
}

func newRepositoryAcquisitionProfileExecution(acquisition RepositoryAcquisitionExecution, bundle analysis.RepositoryProfileBundle, hasProfile bool) (RepositoryAcquisitionProfileExecution, error) {
	if acquisition.Identity() == "" {
		return RepositoryAcquisitionProfileExecution{}, fmt.Errorf("repository acquisition execution is required")
	}
	if acquisition.Outcome() == evidence.AcquisitionOutcomeAcquired {
		if !hasProfile || bundle.Identity() == "" || bundle.ManifestIdentity() != acquisition.Receipt().ManifestIdentity() {
			return RepositoryAcquisitionProfileExecution{}, fmt.Errorf("acquired execution requires a matching repository profile")
		}
	} else if hasProfile || bundle.Identity() != "" {
		return RepositoryAcquisitionProfileExecution{}, fmt.Errorf("non-acquired execution must not include a repository profile")
	}
	profileBundleIdentity := ""
	if hasProfile {
		profileBundleIdentity = bundle.Identity()
	}
	preimage := struct {
		Contract                     string `json:"contract"`
		SchemaVersion                int    `json:"schema_version"`
		AcquisitionExecutionIdentity string `json:"acquisition_execution_identity"`
		ProfilePresent               bool   `json:"profile_present"`
		ProfileBundleIdentity        string `json:"profile_bundle_identity"`
	}{
		Contract:                     "open-trestle/repository-acquisition-profile-execution",
		SchemaVersion:                1,
		AcquisitionExecutionIdentity: acquisition.Identity(),
		ProfilePresent:               hasProfile,
		ProfileBundleIdentity:        profileBundleIdentity,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return RepositoryAcquisitionProfileExecution{}, fmt.Errorf("encode repository acquisition profile execution identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return RepositoryAcquisitionProfileExecution{
		identity:      hex.EncodeToString(digest[:]),
		acquisition:   acquisition,
		hasProfile:    hasProfile,
		profileBundle: bundle,
	}, nil
}
