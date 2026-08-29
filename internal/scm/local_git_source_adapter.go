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
	if a == nil || a.store == nil || isNilInterface(ctx) {
		return localGitSourceAdapterFailure(LocalGitRevisionInvalidGraph)
	}
	if err := evidence.ValidateRepositoryAcquisitionRequest(request); err != nil {
		return localGitSourceAdapterFailure(LocalGitRevisionInvalidGraph)
	}
	if err := ctx.Err(); err != nil {
		return localGitSourceAdapterFailure(err)
	}
	if request.SourceAdapterIdentity() != a.identity.Identity() || request.RepositoryIdentity() != a.store.RepositoryIdentity() {
		return localGitSourceAdapterFailure(LocalGitRevisionInvalidGraph)
	}
	result, err := ReadLocalGitRevision(ctx, a.store, request.Revision())
	if err != nil {
		return localGitSourceAdapterFailure(err)
	}
	if err := ctx.Err(); err != nil {
		return localGitSourceAdapterFailure(err)
	}
	if result.RevisionIdentity() != request.RevisionIdentity() || result.RepositoryIdentity() != request.RepositoryIdentity() || result.Manifest().Identity() == "" {
		return localGitSourceAdapterFailure(LocalGitRevisionInvalidGraph)
	}
	acquired := SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: result.Manifest()}
	switch request.Artifact() {
	case evidence.AcquisitionArtifactManifest:
		return acquired
	case evidence.AcquisitionArtifactManifestAndContent:
		acquired.Contents = result.Contents()
		if err := ctx.Err(); err != nil {
			return localGitSourceAdapterFailure(err)
		}
		return acquired
	default:
		return localGitSourceAdapterFailure(LocalGitRevisionInvalidGraph)
	}
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
