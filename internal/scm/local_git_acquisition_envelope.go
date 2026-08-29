package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// LocalGitAcquisitionEnvelope jointly identifies structural binding and profiling.
type LocalGitAcquisitionEnvelope struct {
	identity            string
	profiledAcquisition RepositoryAcquisitionProfileExecution
	evidenceBinding     evidence.RepositoryAcquisitionEvidenceBinding
}

// Identity returns the versioned canonical SHA-256 identity.
func (e LocalGitAcquisitionEnvelope) Identity() string { return e.identity }

// ProfiledAcquisition returns the compact profiled acquisition execution.
func (e LocalGitAcquisitionEnvelope) ProfiledAcquisition() RepositoryAcquisitionProfileExecution {
	return e.profiledAcquisition
}

// EvidenceBinding returns the structural acquisition evidence binding.
func (e LocalGitAcquisitionEnvelope) EvidenceBinding() evidence.RepositoryAcquisitionEvidenceBinding {
	return e.evidenceBinding
}

// ExecuteLocalGitAcquisitionWithBindingAndProfile derives both results from one acquisition.
func ExecuteLocalGitAcquisitionWithBindingAndProfile(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, error) {
	envelope, _, err := executeLocalGitAcquisitionEnvelopeWithManifest(ctx, request, adapter)
	return envelope, err
}

func executeLocalGitAcquisitionEnvelopeWithManifest(ctx context.Context, request evidence.RepositoryAcquisitionRequest, adapter *LocalGitSourceAdapter) (LocalGitAcquisitionEnvelope, evidence.RepositoryManifest, error) {
	if isNilInterface(ctx) {
		return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, fmt.Errorf("repository acquisition context is nil")
	}
	if adapter == nil {
		return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, fmt.Errorf("source adapter is nil")
	}
	if err := evidence.ValidateRepositoryAcquisitionRequest(request); err != nil {
		return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, err
	}
	if err := ctx.Err(); err != nil {
		return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, err
	}
	if request.Artifact() != evidence.AcquisitionArtifactManifestAndContent {
		return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, fmt.Errorf("local Git acquisition envelope requires manifest and content acquisition")
	}
	runtime, err := executeRepositoryAcquisitionWithRetention(ctx, request, adapter, repositoryAcquisitionRetainBindingInputs)
	if err != nil {
		return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, err
	}
	defer clearRepositoryAcquisitionRuntimeResult(&runtime)
	envelope, err := buildLocalGitAcquisitionEnvelope(ctx, request, runtime)
	if err != nil {
		return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, err
	}
	manifest, err := evidence.NewRepositoryManifest(runtime.result.Manifest.Files())
	if err != nil || manifest.Identity() != envelope.EvidenceBinding().ManifestIdentity() {
		return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, fmt.Errorf("local Git acquisition manifest does not match envelope")
	}
	if err := ctx.Err(); err != nil {
		return LocalGitAcquisitionEnvelope{}, evidence.RepositoryManifest{}, err
	}
	return envelope, manifest, nil
}

func buildLocalGitAcquisitionEnvelope(ctx context.Context, request evidence.RepositoryAcquisitionRequest, runtime repositoryAcquisitionRuntimeResult) (LocalGitAcquisitionEnvelope, error) {
	binding, err := bindLocalGitAcquisitionExecution(ctx, request, runtime)
	if err != nil {
		return LocalGitAcquisitionEnvelope{}, err
	}
	bundle, err := buildRepositoryAcquisitionProfile(ctx, runtime)
	if err != nil {
		return LocalGitAcquisitionEnvelope{}, err
	}
	profiled, err := newRepositoryAcquisitionProfileExecution(runtime.execution, bundle, true)
	if err != nil {
		return LocalGitAcquisitionEnvelope{}, err
	}
	envelope, err := newLocalGitAcquisitionEnvelope(profiled, binding)
	if err != nil {
		return LocalGitAcquisitionEnvelope{}, err
	}
	if err := ctx.Err(); err != nil {
		return LocalGitAcquisitionEnvelope{}, err
	}
	return envelope, nil
}

func clearRepositoryAcquisitionRuntimeResult(runtime *repositoryAcquisitionRuntimeResult) {
	if runtime == nil {
		return
	}
	runtime.result.Contents = nil
	runtime.bindingInputs.commitContent = nil
	runtime.bindingInputs.rootTreeContent = nil
	runtime.bindingInputs.childTreeContents = nil
	runtime.bindingInputs.blobContents = nil
	*runtime = repositoryAcquisitionRuntimeResult{}
}

func newLocalGitAcquisitionEnvelope(profiled RepositoryAcquisitionProfileExecution, binding evidence.RepositoryAcquisitionEvidenceBinding) (LocalGitAcquisitionEnvelope, error) {
	canonicalProfiled, err := newRepositoryAcquisitionProfileExecution(profiled.Acquisition(), profiled.ProfileBundle(), profiled.HasProfile())
	if err != nil || canonicalProfiled != profiled {
		return LocalGitAcquisitionEnvelope{}, fmt.Errorf("profiled acquisition execution is not canonical")
	}
	execution := profiled.Acquisition()
	canonicalExecutionIdentity, err := canonicalRepositoryAcquisitionExecutionIdentity(execution)
	if err != nil || canonicalExecutionIdentity != execution.Identity() {
		return LocalGitAcquisitionEnvelope{}, fmt.Errorf("repository acquisition execution is not canonical")
	}
	receipt := execution.Receipt()
	bundle := profiled.ProfileBundle()
	if execution.Outcome() != evidence.AcquisitionOutcomeAcquired || !execution.HasLocalGitEvidence() || !profiled.HasProfile() || binding.Identity() == "" || binding.BindingStatus() != evidence.RepositoryAcquisitionEvidenceStatusSupplied {
		return LocalGitAcquisitionEnvelope{}, fmt.Errorf("local Git acquisition children are incomplete")
	}
	if binding.RequestIdentity() != execution.RequestIdentity() || binding.RequestIdentity() != receipt.RequestIdentity() || binding.ReceiptIdentity() != execution.ReceiptIdentity() || binding.RepositoryIdentity() != receipt.RepositoryIdentity() || binding.RevisionIdentity() != execution.RevisionIdentity() || binding.RevisionIdentity() != receipt.RevisionIdentity() || binding.SourceAdapterIdentity() != execution.SourceAdapterIdentity() || binding.SourceAdapterIdentity() != receipt.SourceAdapterIdentity() || binding.ManifestIdentity() != execution.ManifestIdentity() || binding.ManifestIdentity() != receipt.ManifestIdentity() || binding.ManifestIdentity() != bundle.ManifestIdentity() || binding.GitCommitIdentity() != execution.GitCommitIdentity() || binding.GitTreeGraphIdentity() != execution.GitTreeGraphIdentity() || binding.CorrespondenceIdentity() != execution.CorrespondenceIdentity() {
		return LocalGitAcquisitionEnvelope{}, fmt.Errorf("local Git acquisition children do not agree")
	}
	preimage := struct {
		Contract                             string `json:"contract"`
		SchemaVersion                        int    `json:"schema_version"`
		ProfiledAcquisitionExecutionIdentity string `json:"profiled_acquisition_execution_identity"`
		EvidenceBindingIdentity              string `json:"evidence_binding_identity"`
	}{
		Contract:                             "open-trestle/local-git-acquisition-envelope",
		SchemaVersion:                        1,
		ProfiledAcquisitionExecutionIdentity: profiled.Identity(),
		EvidenceBindingIdentity:              binding.Identity(),
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return LocalGitAcquisitionEnvelope{}, fmt.Errorf("encode local Git acquisition envelope identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return LocalGitAcquisitionEnvelope{
		identity:            hex.EncodeToString(digest[:]),
		profiledAcquisition: profiled,
		evidenceBinding:     binding,
	}, nil
}
