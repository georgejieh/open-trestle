package scm

import (
	"context"
	"errors"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	localGitSourceAdapterName    = "local-git-loose"
	localGitSourceAdapterVersion = "1.0.0"
)

// LocalGitSourceAdapter acquires supported revisions from one loose-object store.
type LocalGitSourceAdapter struct {
	store    *LocalGitObjectStore
	identity evidence.SourceAdapterIdentity
}

var _ SourceAdapter = (*LocalGitSourceAdapter)(nil)

// NewLocalGitSourceAdapter creates a read-only adapter for one supplied object store.
func NewLocalGitSourceAdapter(store *LocalGitObjectStore) (*LocalGitSourceAdapter, error) {
	if store == nil || store.objectsRoot == nil || store.RepositoryIdentity() == "" {
		return nil, fmt.Errorf("local Git object store is not initialized")
	}
	identity, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, localGitSourceAdapterName, localGitSourceAdapterVersion, []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadContent, evidence.SourceCapabilityReadManifest})
	if err != nil {
		return nil, fmt.Errorf("construct local Git source adapter identity: %w", err)
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
	result, _, _ := a.acquireWithLocalGitEvidence(ctx, request)
	return result
}

func (a *LocalGitSourceAdapter) acquireWithLocalGitEvidence(ctx context.Context, request evidence.RepositoryAcquisitionRequest) (SourceAdapterResult, localGitExecutionEvidence, bool) {
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
	result, err := ReadLocalGitRevision(ctx, a.store, request.Revision())
	if err != nil {
		return localGitSourceAdapterExecutionFailure(err)
	}
	if err := ctx.Err(); err != nil {
		return localGitSourceAdapterExecutionFailure(err)
	}
	if result.RevisionIdentity() != request.RevisionIdentity() || result.RepositoryIdentity() != request.RepositoryIdentity() || result.Manifest().Identity() == "" {
		return localGitSourceAdapterExecutionFailure(LocalGitRevisionInvalidGraph)
	}
	localGitEvidence, err := newLocalGitExecutionEvidence(result)
	if err != nil {
		return localGitSourceAdapterExecutionFailure(err)
	}
	if err := ctx.Err(); err != nil {
		return localGitSourceAdapterExecutionFailure(err)
	}
	acquired := SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: result.Manifest()}
	switch request.Artifact() {
	case evidence.AcquisitionArtifactManifest:
		return acquired, localGitEvidence, true
	case evidence.AcquisitionArtifactManifestAndContent:
		acquired.Contents = result.contents
		if err := ctx.Err(); err != nil {
			return localGitSourceAdapterExecutionFailure(err)
		}
		return acquired, localGitEvidence, true
	default:
		return localGitSourceAdapterExecutionFailure(LocalGitRevisionInvalidGraph)
	}
}

func localGitSourceAdapterExecutionFailure(err error) (SourceAdapterResult, localGitExecutionEvidence, bool) {
	return localGitSourceAdapterFailure(err), localGitExecutionEvidence{}, false
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
