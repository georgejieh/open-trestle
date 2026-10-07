package runtimecatalog

import (
	"context"
	"errors"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// LocalRevisionValidator re-proves exact revisions through the daemon-owned object store.
type LocalRevisionValidator interface {
	RepositoryIdentity() string
	ValidateLocalRevision(context.Context, evidence.RevisionIdentity) error
}

// LocalFullReviewAdmissionConfig is daemon-owned source and local route authority.
type LocalFullReviewAdmissionConfig struct {
	Source             LocalRevisionValidator
	Repository         evidence.RepositoryIdentity
	SourceAdapter      evidence.SourceAdapterIdentity
	SourceRootIdentity string
	Inventory          runtimeconfig.RouteInventory
	Policy             runtimeconfig.RuntimePolicy
	Classification     artifact.Classification
	Protection         artifact.Protection
	Retention          time.Duration
	Catalog            PipelineCatalog
}

type LocalFullReviewAdmitter struct {
	coordinator *controlplane.Coordinator
	store       artifact.Store
	config      LocalFullReviewAdmissionConfig
}

func NewLocalFullReviewAdmitter(journal controlplane.RunJournal, store artifact.Store, config LocalFullReviewAdmissionConfig) (*LocalFullReviewAdmitter, error) {
	if nilLocalValue(journal) || nilLocalValue(store) || validateLocalFullAdmissionConfig(config) != nil {
		return nil, ErrInvalidLocalFullReview
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		return nil, ErrInvalidLocalFullReview
	}
	return &LocalFullReviewAdmitter{coordinator, store, config}, nil
}

func validateLocalFullAdmissionConfig(c LocalFullReviewAdmissionConfig) error {
	repository, err := evidence.NewRepositoryIdentity(c.Repository.Authority(), c.Repository.Namespace(), c.Repository.Name())
	adapter, adapterErr := evidence.NewSourceAdapterIdentity(c.SourceAdapter.Kind(), c.SourceAdapter.Name(), c.SourceAdapter.Version(), c.SourceAdapter.Capabilities())
	if err != nil || repository.Identity() != c.Repository.Identity() || nilLocalValue(c.Source) || c.Source.RepositoryIdentity() != c.Repository.Identity() || adapterErr != nil || adapter.Identity() != c.SourceAdapter.Identity() || c.SourceAdapter.Kind() != evidence.SourceAdapterKindGit || controlplane.ValidateHandlerIdentity(c.SourceRootIdentity) != nil || c.Inventory.Validate() != nil || c.Policy.ValidateAgainstInventory(c.Inventory) != nil || c.Classification.String() == "" || c.Protection != artifact.ProtectionProcessPrivate || c.Retention < time.Minute || c.Retention > 24*time.Hour || c.Catalog.Validate() != nil || c.Catalog.Mode() != controlplane.ReviewRunLocal || len(c.Catalog.Bindings()) != 8 {
		return ErrInvalidLocalFullReview
	}
	zones := c.Policy.Constraints().AllowedProviderZones()
	if !zones.Allows(provider.ProviderZoneLocal) || c.Policy.Constraints().ContentLoggingAllowed() {
		return ErrInvalidLocalFullReview
	}
	for zone := provider.ProviderZoneLocal + 1; zone <= provider.ProviderZoneSubscriptionOAuth; zone++ {
		if zones.Allows(zone) {
			return ErrInvalidLocalFullReview
		}
	}
	references := map[provider.RouteReference]struct{}{}
	for _, candidate := range c.Inventory.Candidates() {
		route := candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		if route.Zone() != provider.ProviderZoneLocal {
			return ErrInvalidLocalFullReview
		}
		references[route] = struct{}{}
	}
	if len(references) < 2 {
		return ErrInvalidLocalFullReview
	}
	return nil
}

func (a *LocalFullReviewAdmitter) Admit(ctx context.Context, intent LocalFullReviewIntent, at time.Time) (controlplane.ReviewRunState, error) {
	if a == nil || a.coordinator == nil || nilLocalValue(a.store) || ctx == nil || ctx.Err() != nil || intent.Validate() != nil || validateLocalFullAdmissionConfig(a.config) != nil {
		return controlplane.ReviewRunState{}, ErrInvalidLocalFullReview
	}
	if intent.Repository().Identity() != a.config.Repository.Identity() || intent.ReviewPolicyIdentity() != a.config.Policy.ReviewPolicyIdentity() || intent.InventoryIdentity() != a.config.Inventory.Identity() || intent.RuntimePolicyIdentity() != a.config.Policy.Identity() {
		return controlplane.ReviewRunState{}, ErrInvalidLocalFullReview
	}
	request, err := NewPreparedReviewRequest(PreparedReviewRequestOptions{Scope: intent.Scope(), HostRequestIdentity: intent.Identity(), Repository: intent.Repository(), BaseRevision: intent.BaseRevision(), HeadRevision: intent.HeadRevision(), SourceAdapter: a.config.SourceAdapter, SourceRootIdentity: a.config.SourceRootIdentity, InventoryIdentity: a.config.Inventory.Identity(), RuntimePolicyIdentity: a.config.Policy.Identity(), ReviewPolicyIdentity: a.config.Policy.ReviewPolicyIdentity(), Classification: a.config.Classification, Protection: a.config.Protection, CreatedAt: intent.CreatedAt(), Retention: a.config.Retention, Catalog: a.config.Catalog, RequireBoundSource: true})
	if err != nil {
		return controlplane.ReviewRunState{}, ErrInvalidLocalFullReview
	}
	prepared, err := PrepareReviewRun(ctx, request)
	if err != nil {
		return controlplane.ReviewRunState{}, err
	}
	plan := prepared.Plan()
	existing, _, resumeErr := a.coordinator.Resume(ctx, intent.Scope())
	if resumeErr == nil {
		if existing.Identity() != plan.Identity() {
			return controlplane.ReviewRunState{}, ErrLocalFullReviewConflict
		}
		return a.coordinator.Advance(ctx, existing, at.UTC())
	}
	if !errors.Is(resumeErr, controlplane.ErrRunNotOpened) {
		return controlplane.ReviewRunState{}, resumeErr
	}
	at = at.UTC()
	if at.Before(intent.CreatedAt()) || at.Sub(intent.CreatedAt()) > localDeterministicIntentFreshness || !intent.CreatedAt().Add(a.config.Retention).After(at) {
		return controlplane.ReviewRunState{}, ErrLocalFullReviewExpired
	}
	for _, revision := range []evidence.RevisionIdentity{intent.BaseRevision(), intent.HeadRevision()} {
		if err := a.config.Source.ValidateLocalRevision(ctx, revision); err != nil {
			if errors.Is(err, scm.LocalGitRevisionResourceLimit) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return controlplane.ReviewRunState{}, err
			}
			return controlplane.ReviewRunState{}, ErrInvalidLocalFullReview
		}
	}
	for _, input := range prepared.Inputs() {
		if input.Scope().Identity() != intent.Scope().Identity() || !input.ExpiresAt().After(at) {
			return controlplane.ReviewRunState{}, ErrInvalidLocalFullReview
		}
		if _, err := a.store.Put(ctx, input, at); err != nil {
			return controlplane.ReviewRunState{}, err
		}
	}
	state, err := a.coordinator.Open(ctx, plan, at)
	if err == nil {
		state, err = a.coordinator.Advance(ctx, plan, at)
	}
	return state, err
}
