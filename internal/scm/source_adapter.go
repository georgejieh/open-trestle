package scm

import (
	"context"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// SourceAdapter performs one provider-neutral repository acquisition.
type SourceAdapter interface {
	Identity() evidence.SourceAdapterIdentity
	Acquire(context.Context, evidence.RepositoryAcquisitionRequest) SourceAdapterResult
}

// SourceAdapterResult carries typed candidate evidence from one adapter call.
type SourceAdapterResult struct {
	Outcome  evidence.RepositoryAcquisitionOutcome
	Reason   evidence.RepositoryAcquisitionReason
	Manifest evidence.RepositoryManifest
	Contents map[string][]byte
}
