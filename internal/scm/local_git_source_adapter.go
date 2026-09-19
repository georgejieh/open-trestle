package scm

import (
	"context"
	"errors"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	localGitSourceAdapterName       = "local-git-loose"
	localGitPackedSourceAdapterName = "local-git-loose-and-pack-index-v1"
	localGitSourceAdapterVersion    = "1.0.0"
)

// Bound combined object and path content retained during exact binding.
const maxLocalGitBindingRetainedContentBytes = 256 << 20

// LocalGitSourceAdapter acquires supported revisions from one loose-object store.
type LocalGitSourceAdapter struct {
	store    *LocalGitObjectStore
	identity evidence.SourceAdapterIdentity
}

var _ SourceAdapter = (*LocalGitSourceAdapter)(nil)

type localGitAdapterAcquisition struct {
	result            SourceAdapterResult
	executionEvidence localGitExecutionEvidence
	bindingInputs     localGitEvidenceInputs
	hasEvidence       bool
	hasBindingInputs  bool
}

// NewLocalGitSourceAdapter creates a read-only loose-only adapter for one supplied object store.
func NewLocalGitSourceAdapter(store *LocalGitObjectStore) (*LocalGitSourceAdapter, error) {
	if store == nil || store.objectsRoot == nil || store.RepositoryIdentity() == "" {
		return nil, fmt.Errorf("local Git object store is not initialized")
	}
	if store.Profile() != LocalGitObjectStoreProfileLooseOnly {
		return nil, fmt.Errorf("local Git loose adapter requires the loose-only object store profile")
	}
	identity, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, localGitSourceAdapterName, localGitSourceAdapterVersion, []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadContent, evidence.SourceCapabilityReadManifest})
	if err != nil {
		return nil, fmt.Errorf("construct local Git source adapter identity: %w", err)
	}
	return &LocalGitSourceAdapter{store: store, identity: identity}, nil
}

// NewLocalGitPackedSourceAdapter creates the explicit opt-in loose-and-pack-index-v1 adapter.
func NewLocalGitPackedSourceAdapter(store *LocalGitObjectStore) (*LocalGitSourceAdapter, error) {
	if store == nil || store.objectsRoot == nil || store.RepositoryIdentity() == "" {
		return nil, fmt.Errorf("local Git object store is not initialized")
	}
	if store.Profile() != LocalGitObjectStoreProfileLooseAndPackIndexV1 || store.ProfileIdentity() != localGitObjectStorePackedProfileIdentity {
		return nil, fmt.Errorf("local Git packed adapter requires the loose-and-pack-index-v1 object store profile")
	}
	identity, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, localGitPackedSourceAdapterName, localGitSourceAdapterVersion, []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadContent, evidence.SourceCapabilityReadManifest})
	if err != nil {
		return nil, fmt.Errorf("construct local Git packed source adapter identity: %w", err)
	}
	if identity.Identity() != "aa61d1b44f36ebcf330492606154d877f1f9c6faeb681a07ebb9fd286e6ce286" {
		return nil, fmt.Errorf("local Git packed source adapter identity preimage mismatch")
	}
	return &LocalGitSourceAdapter{store: store, identity: identity}, nil
}

// Identity returns the adapter's static canonical self-description.
func (a *LocalGitSourceAdapter) Identity() evidence.SourceAdapterIdentity {
	if a == nil {
		return evidence.SourceAdapterIdentity{}
	}
	return a.identity
}

// Acquire reads one exact requested revision and returns typed candidate evidence.
func (a *LocalGitSourceAdapter) Acquire(ctx context.Context, request evidence.RepositoryAcquisitionRequest) SourceAdapterResult {
	return a.acquire(ctx, request, false).result
}

func (a *LocalGitSourceAdapter) acquireWithLocalGitEvidence(ctx context.Context, request evidence.RepositoryAcquisitionRequest) (SourceAdapterResult, localGitExecutionEvidence, bool) {
	acquisition := a.acquire(ctx, request, false)
	return acquisition.result, acquisition.executionEvidence, acquisition.hasEvidence
}

func (a *LocalGitSourceAdapter) acquireWithLocalGitBindingInputs(ctx context.Context, request evidence.RepositoryAcquisitionRequest) (SourceAdapterResult, localGitExecutionEvidence, localGitEvidenceInputs, bool) {
	acquisition := a.acquire(ctx, request, true)
	return acquisition.result, acquisition.executionEvidence, acquisition.bindingInputs, acquisition.hasEvidence && acquisition.hasBindingInputs
}

func (a *LocalGitSourceAdapter) acquire(ctx context.Context, request evidence.RepositoryAcquisitionRequest, retainBindingInputs bool) localGitAdapterAcquisition {
	if a == nil || a.store == nil || isNilInterface(ctx) {
		return localGitSourceAdapterExecutionFailure(LocalGitRevisionInvalidGraph)
	}
	if err := evidence.ValidateRepositoryAcquisitionRequest(request); err != nil {
		return localGitSourceAdapterExecutionFailure(LocalGitRevisionInvalidGraph)
	}
	if err := ctx.Err(); err != nil {
		return localGitSourceAdapterExecutionFailure(err)
	}
	if request.SourceAdapterIdentity() != a.identity.Identity() || request.RepositoryIdentity() != a.store.RepositoryIdentity() {
		return localGitSourceAdapterExecutionFailure(LocalGitRevisionInvalidGraph)
	}
	var result LocalGitRevisionResult
	var bindingInputs localGitEvidenceInputs
	var err error
	if retainBindingInputs {
		limits := standardLocalGitRevisionLimits()
		limits.maxRetainedBytes = maxLocalGitBindingRetainedContentBytes
		result, bindingInputs, err = readLocalGitRevisionWithInputs(ctx, a.store, request.Revision(), limits)
	} else {
		result, err = ReadLocalGitRevision(ctx, a.store, request.Revision())
	}
	if err != nil {
		return localGitSourceAdapterExecutionFailure(err)
	}
	if err := ctx.Err(); err != nil {
		return localGitSourceAdapterExecutionFailure(err)
	}
	if result.RevisionIdentity() != request.RevisionIdentity() || result.RepositoryIdentity() != request.RepositoryIdentity() || result.Manifest().Identity() == "" {
		return localGitSourceAdapterExecutionFailure(LocalGitRevisionInvalidGraph)
	}
	if retainBindingInputs {
		if err := validateLocalGitBindingRetainedContent(ctx, bindingInputs, result.TotalContentBytes()); err != nil {
			return localGitSourceAdapterExecutionFailure(err)
		}
	}
	executionEvidence, err := newLocalGitExecutionEvidence(result)
	if err != nil {
		return localGitSourceAdapterExecutionFailure(err)
	}
	if err := ctx.Err(); err != nil {
		return localGitSourceAdapterExecutionFailure(err)
	}
	acquired := SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: result.Manifest()}
	switch request.Artifact() {
	case evidence.AcquisitionArtifactManifest:
	case evidence.AcquisitionArtifactManifestAndContent:
		acquired.Contents = result.contents
		result.contents = nil
	default:
		return localGitSourceAdapterExecutionFailure(LocalGitRevisionInvalidGraph)
	}
	if err := ctx.Err(); err != nil {
		return localGitSourceAdapterExecutionFailure(err)
	}
	return localGitAdapterAcquisition{
		result:            acquired,
		executionEvidence: executionEvidence,
		bindingInputs:     bindingInputs,
		hasEvidence:       true,
		hasBindingInputs:  retainBindingInputs,
	}
}

func localGitSourceAdapterExecutionFailure(err error) localGitAdapterAcquisition {
	return localGitAdapterAcquisition{result: localGitSourceAdapterFailure(err)}
}

func validateLocalGitBindingRetainedContent(ctx context.Context, inputs localGitEvidenceInputs, resultContentBytes int64) error {
	objectBytes, err := checkedLocalGitRevisionAdd(0, int64(len(inputs.rootTreeContent)), maxLocalGitBindingRetainedContentBytes)
	if err != nil {
		return LocalGitRevisionResourceLimit
	}
	for _, objects := range []map[string][]byte{inputs.childTreeContents, inputs.blobContents} {
		for _, content := range objects {
			if err := ctx.Err(); err != nil {
				return err
			}
			objectBytes, err = checkedLocalGitRevisionAdd(objectBytes, int64(len(content)), maxLocalGitBindingRetainedContentBytes)
			if err != nil {
				return LocalGitRevisionResourceLimit
			}
		}
	}
	if objectBytes != inputs.graph.TotalObjectBytes() {
		return LocalGitRevisionInvalidGraph
	}
	total, err := checkedLocalGitRevisionAdd(0, int64(len(inputs.commitContent)), maxLocalGitBindingRetainedContentBytes)
	if err != nil {
		return LocalGitRevisionResourceLimit
	}
	total, err = checkedLocalGitRevisionAdd(total, objectBytes, maxLocalGitBindingRetainedContentBytes)
	if err != nil {
		return LocalGitRevisionResourceLimit
	}
	if _, err := checkedLocalGitRevisionAdd(total, resultContentBytes, maxLocalGitBindingRetainedContentBytes); err != nil {
		return LocalGitRevisionResourceLimit
	}
	return ctx.Err()
}

func localGitSourceAdapterFailure(err error) SourceAdapterResult {
	switch {
	case errors.Is(err, LocalGitRevisionObjectUnavailable), errors.Is(err, LocalGitRevisionUnsupportedSymlink), errors.Is(err, LocalGitRevisionUnsupportedGitlink):
		return SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeFailed, Reason: evidence.AcquisitionReasonArtifactIncomplete}
	case errors.Is(err, LocalGitRevisionResourceLimit):
		return SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeFailed, Reason: evidence.AcquisitionReasonResourceLimit}
	default:
		return SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeFailed, Reason: evidence.AcquisitionReasonAdapterFailure}
	}
}
