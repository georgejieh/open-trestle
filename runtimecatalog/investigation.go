package runtimecatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysis "github.com/georgejieh/open-trestle/handlers/analysis"
	change "github.com/georgejieh/open-trestle/handlers/change"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	model "github.com/georgejieh/open-trestle/handlers/model"
	publication "github.com/georgejieh/open-trestle/handlers/publication"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

var ErrInvalidInvestigationCatalog = errors.New("invalid investigation pipeline catalog")

// NewInvestigationProfileFromRuntimePolicy is pure configuration composition.
// It neither resolves credentials nor creates model/task claims.
func NewInvestigationProfileFromRuntimePolicy(configuration runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, policy review.InvestigationPolicy, catalogIdentity string) (model.InvestigationPipelineProfile, error) {
	if configuration.ValidateAgainstInventory(inventory) != nil || inventory.Validate() != nil || configuration.InventoryIdentity() != inventory.Identity() || policy.ValidateRuntimeBudget(configuration.Budget()) != nil {
		return model.InvestigationPipelineProfile{}, ErrInvalidInvestigationCatalog
	}
	pin, ok := configuration.Ranking().PinnedRoute()
	if !ok {
		return model.InvestigationPipelineProfile{}, ErrInvalidInvestigationCatalog
	}
	var generation gateway.ObservedRouteCandidate
	verification := []gateway.ObservedRouteCandidate{}
	for _, candidate := range inventory.Candidates() {
		reference := candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		if reference == pin {
			if generation.ResolvedRecord().RouteRegistryRecord().Identity() != "" {
				return model.InvestigationPipelineProfile{}, ErrInvalidInvestigationCatalog
			}
			generation = candidate
		} else {
			verification = append(verification, candidate)
		}
	}
	if generation.Validate() != nil || len(verification) == 0 {
		return model.InvestigationPipelineProfile{}, ErrInvalidInvestigationCatalog
	}
	ranking, err := gateway.NewRouteRankingPolicy(configuration.Ranking().PreferredRoutes())
	if err != nil {
		return model.InvestigationPipelineProfile{}, ErrInvalidInvestigationCatalog
	}
	budget, err := provider.NewModelCostBudget(uint64(configuration.Budget().EstimatedInputTokens()), uint64(configuration.Budget().MaxOutputTokens()), policy.MaxCostMicroUSD())
	if err != nil {
		return model.InvestigationPipelineProfile{}, ErrInvalidInvestigationCatalog
	}
	routing := model.InvestigationRoutingOptions{RegistryRevision: inventory.RegistryRevision(), PerformanceRevision: inventory.PerformanceRevision(), Generation: generation, Verification: verification, Observations: inventory.PerformanceObservations(), VerificationRanking: ranking, Requirements: configuration.Requirements(), Constraints: configuration.Constraints(), Budget: budget, Independence: configuration.Independence()}
	return model.NewInvestigationPipelineProfile(model.InvestigationPipelineProfileOptions{RuntimePolicyIdentity: configuration.Identity(), InventoryIdentity: inventory.Identity(), ReviewPolicyIdentity: configuration.ReviewPolicyIdentity(), PublicationPolicyIdentity: configuration.Publication().Identity(), PublicationPolicy: configuration.Publication(), DispatcherCatalogIdentity: catalogIdentity, Policy: policy, Routing: routing})
}

type InvestigationCatalogOptions struct {
	Store       artifact.Store
	Diagnostics diagnostics.Store
	Ledger      audit.Ledger
	Journal     controlplane.RunJournal
	Clock       artifact.Clock
	Dispatchers gateway.RouteDispatcherCatalog
	Source      scm.SourceAdapter
}

// NewInvestigationPipelineCatalog creates actual inert handlers, not a parallel engine.
func NewInvestigationPipelineCatalog(profile model.InvestigationPipelineProfile, o InvestigationCatalogOptions) (PipelineCatalog, *model.InvestigationPipeline, error) {
	if profile.Validate() != nil || o.Dispatchers.Validate() != nil || o.Dispatchers.Identity() != profile.DispatcherCatalogIdentity() {
		return PipelineCatalog{}, nil, ErrInvalidInvestigationCatalog
	}
	changes, err := change.NewHandler(o.Store, o.Clock)
	if err != nil {
		return PipelineCatalog{}, nil, err
	}
	analyses, err := analysis.NewHandler(o.Store, o.Clock)
	if err != nil {
		return PipelineCatalog{}, nil, err
	}
	hash := sha256.Sum256([]byte("empty-memory-index-v1"))
	indexID := hex.EncodeToString(hash[:])
	memories, err := memoryhandler.NewHandler(o.Store, o.Clock, memory.NewLexicalIndex(), indexID, profile.ReviewPolicyIdentity(), "local-reviewer", []string{"."}, 10, 20)
	if err != nil {
		return PipelineCatalog{}, nil, err
	}
	bridge, err := model.NewInvestigationPipeline(model.InvestigationPipelineOptions{Profile: profile, Store: o.Store, Ledger: o.Ledger, Journal: o.Journal, Clock: o.Clock, Catalog: o.Dispatchers, Source: o.Source, Support: model.InvestigationSupportBindings{Change: changes.HandlerIdentity(), Analysis: analyses.HandlerIdentity(), Memory: memories.HandlerIdentity()}})
	if err != nil {
		return PipelineCatalog{}, nil, err
	}
	sources, err := model.NewInvestigationSourceTaskHandler(bridge)
	if err != nil {
		return PipelineCatalog{}, nil, err
	}
	assembly, err := contexthandler.NewInvestigationHandler(o.Store, o.Clock, bridge)
	if err != nil {
		return PipelineCatalog{}, nil, err
	}
	generation, err := model.NewInvestigationGenerationTaskHandler(bridge)
	if err != nil {
		return PipelineCatalog{}, nil, err
	}
	verification, err := model.NewInvestigationVerificationTaskHandler(bridge)
	if err != nil {
		return PipelineCatalog{}, nil, err
	}
	readiness, err := publication.NewInvestigationReadinessHandler(o.Store, o.Diagnostics, o.Clock, profile.ReviewPolicyIdentity(), profile.PublicationPolicy(), bridge)
	if err != nil {
		return PipelineCatalog{}, nil, err
	}
	catalog, err := NewPipelineCatalog(controlplane.ReviewRunLocal, []controlplane.TaskHandler{sources, changes, analyses, memories, assembly, generation, verification, readiness})
	if err != nil {
		return PipelineCatalog{}, nil, err
	}
	return catalog, bridge, nil
}
