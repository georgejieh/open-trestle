package runtimecatalog_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	githubwebhook "github.com/georgejieh/open-trestle/adapters/webhook/github"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	publicationhandler "github.com/georgejieh/open-trestle/handlers/publication"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"github.com/georgejieh/open-trestle/webhook"
)

func requiredCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func requiredDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type requiredClock struct{ at time.Time }

func (c *requiredClock) Now() time.Time { return c.at }

func (c *requiredClock) step() time.Time {
	c.at = c.at.Add(time.Millisecond)
	return c.at
}

type requiredSource struct {
	t        *testing.T
	identity evidence.SourceAdapterIdentity
	results  map[string]scm.SourceAdapterResult
	calls    int
}

func (s *requiredSource) Identity() evidence.SourceAdapterIdentity { return s.identity }

func (s *requiredSource) Acquire(ctx context.Context, request evidence.RepositoryAcquisitionRequest) scm.SourceAdapterResult {
	s.calls++
	if ctx.Err() != nil || s.calls > 2 {
		s.t.Fatal("unexpected source acquisition")
	}
	result, ok := s.results[request.Revision().Identity()]
	if !ok {
		s.t.Fatal("source acquisition requested an unapproved revision")
	}
	return result
}

type requiredRequestSource struct {
	ID        string `json:"source_id"`
	Stage     string `json:"stage"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Content   string `json:"content"`
}

type requiredModel struct {
	t         *testing.T
	adapterID string
	calls     int
	request   gateway.RouteDispatchRequest
	candidate string
	evidence  []string
}

func (m *requiredModel) AdapterID() string             { return m.adapterID }
func (m *requiredModel) ConfigurationIdentity() string { return requiredDigest(m.adapterID) }

func (m *requiredModel) DispatchRoute(ctx context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	m.calls++
	if ctx.Err() != nil || m.calls != 1 {
		m.t.Fatal("model dispatched more than once")
	}
	requiredCheck(m.t, request.Validate())
	m.request = request
	var packet struct {
		Task       string                  `json:"task"`
		Sources    []requiredRequestSource `json:"sources"`
		Candidates []struct {
			ID       string   `json:"candidate_id"`
			Evidence []string `json:"evidence_ids"`
		} `json:"candidates"`
	}
	requiredCheck(m.t, json.Unmarshal(request.Request().Payload(), &packet))
	var changed, caller requiredRequestSource
	for _, source := range packet.Sources {
		switch source.Path {
		case "a.go":
			changed = source
		case "caller.go":
			caller = source
		}
	}
	if changed.ID == "" || caller.ID == "" || changed.Stage != "changed_hunk" || caller.Stage != "direct_reference" || !strings.Contains(changed.Content, "return 10 / x") || !strings.Contains(caller.Content, "Changed(0)") || changed.StartLine > 2 || changed.EndLine < 2 {
		m.t.Fatal("model request omitted the changed division or unchanged zero-valued caller")
	}
	m.evidence = []string{changed.ID, caller.ID}
	var document map[string]any
	switch packet.Task {
	case "candidate_generation":
		if m.adapterID != "adapter-a" || len(packet.Candidates) != 0 {
			m.t.Fatal("generation did not retain its pinned route")
		}
		document = map[string]any{"schema_version": 1, "candidates": []any{map[string]any{
			"title": "Zero-valued caller now panics", "claim": "Consume calls Changed(0), but Changed now divides by x without the previous zero guard.", "severity_hint": "high",
			"source_range": map[string]any{"source_id": changed.ID, "start_line": 2, "end_line": 2}, "evidence_ids": m.evidence,
		}}}
	case "candidate_verification":
		if m.adapterID != "adapter-b" || len(packet.Candidates) != 1 || packet.Candidates[0].ID == "" {
			m.t.Fatal("verifier did not receive the actual generation candidate")
		}
		m.candidate = packet.Candidates[0].ID
		document = map[string]any{"schema_version": 1, "verdicts": []any{map[string]any{
			"candidate_id": m.candidate, "outcome": "verified", "severity": "high", "rationale": "The cited caller passes zero to the unguarded integer division, which panics.", "evidence_ids": m.evidence,
		}}}
	default:
		m.t.Fatalf("unexpected model task %q", packet.Task)
	}
	payload, err := json.Marshal(document)
	requiredCheck(m.t, err)
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", payload)
	requiredCheck(m.t, err)
	usage, err := provider.NewRouteTokenUsage(100, 100, 0)
	requiredCheck(m.t, err)
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	requiredCheck(m.t, err)
	result, err := gateway.NewSuccessfulRouteDispatchResult(response)
	requiredCheck(m.t, err)
	return result
}

type requiredPublisher struct {
	t           *testing.T
	clock       *requiredClock
	scope       audit.ReviewScope
	target      review.PublicationTarget
	currentHead evidence.RevisionIdentity
	headCalls   int
	calls       int
	request     review.PublicationDispatchRequest
}

const requiredExternalReference = "https://github.com/owner/repository/pull/42#pullrequestreview-123"

func (p *requiredPublisher) PublisherID() string           { return "github-review" }
func (p *requiredPublisher) ResolverID() string            { return "github-review" }
func (p *requiredPublisher) ConfigurationIdentity() string { return requiredDigest("publisher") }
func (p *requiredPublisher) IdempotencyGuarantee() review.PublisherIdempotencyGuarantee {
	return review.PublisherExactOperationKey
}

func (p *requiredPublisher) ResolveHead(ctx context.Context, request review.PublicationHeadRequest) review.PublicationHeadObservation {
	p.headCalls++
	requiredCheck(p.t, request.Validate())
	if ctx.Err() != nil || p.headCalls != 1 || request.Scope().Identity() != p.scope.Identity() || request.Target().Identity() != p.target.Identity() {
		p.t.Fatal("unexpected publication head request")
	}
	observation, err := review.NewResolvedPublicationHeadObservation(p.currentHead)
	requiredCheck(p.t, err)
	return observation
}

func (p *requiredPublisher) Publish(ctx context.Context, request review.PublicationDispatchRequest) review.PublicationResult {
	p.calls++
	requiredCheck(p.t, request.ValidateAt(p.clock.Now()))
	plan := request.Authorization().Plan()
	if ctx.Err() != nil || p.calls != 1 || p.headCalls != 1 || request.Scope().Identity() != p.scope.Identity() || plan.Target().Identity() != p.target.Identity() || !plan.HasAcquiredSource() || plan.SourceRepositoryIdentity() != p.target.RepositoryIdentity().Identity() || plan.SourceHeadRevisionIdentity() != p.target.HeadRevision().Identity() || !request.HeadGate().AuthorizesPublication() || len(plan.InlineFindings()) != 1 || plan.SummaryOnlyFindingCount() != 0 {
		p.t.Fatal("publisher received an unbound or duplicate request")
	}
	p.request = request
	result, err := review.NewSuccessfulPublicationResult(requiredExternalReference)
	requiredCheck(p.t, err)
	return result
}

type requiredPipeline struct {
	t             *testing.T
	clock         *requiredClock
	store         artifact.Store
	ledger        audit.Ledger
	journal       controlplane.RunJournal
	coordinator   *controlplane.Coordinator
	plan          controlplane.ReviewRunPlan
	catalog       runtimecatalog.PipelineCatalog
	configuration runtimeconfig.RuntimePolicy
	source        *requiredSource
	generation    *requiredModel
	verification  *requiredModel
	publisher     *requiredPublisher
	requests      map[string]controlplane.TaskExecutionRequest
	completions   map[string]controlplane.TaskCompletion
}

func requiredRuntimePolicy(t *testing.T, approvedVerifier bool) (runtimeconfig.RuntimePolicy, runtimeconfig.RouteInventory) {
	t.Helper()
	capabilities, err := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	requiredCheck(t, err)
	pricing, err := provider.NewRoutePricing(0, 0)
	requiredCheck(t, err)
	definitions := make([]runtimeconfig.RouteDefinition, 2)
	for i, name := range []string{"a", "b"} {
		route, err := provider.NewRouteReference(provider.ProviderZonePrivateRemote, "provider-"+name, "adapter-"+name, "connection-"+name, "model-"+name, "")
		requiredCheck(t, err)
		status := provider.RouteRegistryApproved
		if i == 1 && !approvedVerifier {
			status = provider.RouteRegistryPending
		}
		definitions[i] = runtimeconfig.RouteDefinition{Route: route, Capabilities: capabilities, ContentLogging: provider.ContentLoggingDisabled, Pricing: pricing, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: status, EvidenceManifest: []byte(`{"fixture":"operator-reviewed local adapter contract"}`), OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11, P95LatencyMilliseconds: 2500, LatencySampleCount: 100}
	}
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), definitions)
	requiredCheck(t, err)
	records := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		records[record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = record.Identity()
	}
	document, err := json.Marshal(map[string]any{
		"schema_version": 1, "inventory_identity": inventory.Identity(), "review_policy_identity": requiredDigest("review-policy"),
		"min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"},
		"classification": "confidential", "allowed_zones": []string{"private_remote"}, "content_logging_allowed": false,
		"estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": 0,
		"pinned_route_record_identity": records["adapter-a"], "preferred_route_record_identities": []string{records["adapter-b"]},
		"verification_independence": "distinct_provider", "publication_minimum_severity": "medium", "publication_max_inline_findings": 20,
		"publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true,
		"connections": []map[string]string{
			{"implementation": "openai_responses", "adapter_id": "adapter-a", "endpoint": "https://provider-a.invalid", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_A"},
			{"implementation": "openai_responses", "adapter_id": "adapter-b", "endpoint": "https://provider-b.invalid", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_B"},
		},
	})
	requiredCheck(t, err)
	configuration, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(document), inventory)
	requiredCheck(t, err)
	return configuration, inventory
}

func newRequiredPipeline(t *testing.T, approvedVerifier, staleHead bool) *requiredPipeline {
	t.Helper()
	ctx := context.Background()
	clock := &requiredClock{at: time.UnixMilli(1000)}
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	requiredCheck(t, err)
	ledger := audit.NewMemoryLedger()
	configuration, inventory := requiredRuntimePolicy(t, approvedVerifier)
	generationAuthority, err := runtimecatalog.NewGenerationPolicyAuthorizerFromRuntimePolicy(configuration, inventory, ledger)
	requiredCheck(t, err)
	verifierInventory, err := runtimecatalog.NewStaticVerificationRouteInventory(inventory)
	requiredCheck(t, err)
	verificationAuthority, err := runtimecatalog.NewVerificationPolicyAuthorizerFromRuntimePolicy(configuration, verifierInventory, ledger, clock)
	requiredCheck(t, err)
	adapterIdentity, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test-source", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	requiredCheck(t, err)
	base, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	requiredCheck(t, err)
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	requiredCheck(t, err)
	acquired := func(body string) scm.SourceAdapterResult {
		contents := map[string][]byte{"a.go": []byte(body), "caller.go": []byte("package p\nfunc Consume() int { return Changed(0) }\n")}
		var sourceFiles []evidence.RepositoryFile
		for _, path := range []string{"a.go", "caller.go"} {
			file, err := evidence.NewRepositoryFile(path, contents[path])
			requiredCheck(t, err)
			sourceFiles = append(sourceFiles, file)
		}
		manifest, err := evidence.NewRepositoryManifest(sourceFiles)
		requiredCheck(t, err)
		return scm.SourceAdapterResult{Outcome: evidence.AcquisitionOutcomeAcquired, Reason: evidence.AcquisitionReasonNone, Manifest: manifest, Contents: contents}
	}
	source := &requiredSource{t: t, identity: adapterIdentity, results: map[string]scm.SourceAdapterResult{
		base.Identity(): acquired("package p\nfunc Changed(x int) int { if x == 0 { return 0 }; return 10 / x }\n"),
		head.Identity(): acquired("package p\nfunc Changed(x int) int { return 10 / x }\n"),
	}}
	generation := &requiredModel{t: t, adapterID: "adapter-a"}
	verification := &requiredModel{t: t, adapterID: "adapter-b"}
	dispatchers, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{generation, verification})
	requiredCheck(t, err)
	publisher := &requiredPublisher{t: t, clock: clock, currentHead: head}
	if staleHead {
		publisher.currentHead = base
	}
	publishers, err := review.NewPublisherCatalog([]review.Publisher{publisher})
	requiredCheck(t, err)
	resolvers, err := review.NewHeadResolverCatalog([]review.HeadResolver{publisher})
	requiredCheck(t, err)
	effectAuthority, err := review.NewRepositoryPublicationAuthorizer("tenant-a", "repo-a", configuration.ReviewPolicyIdentity(), requiredDigest("repository-publication-operator"), time.Hour)
	requiredCheck(t, err)
	sourceHandler, err := sourcehandler.NewHandler(store, source, clock)
	requiredCheck(t, err)
	change, err := changehandler.NewHandler(store, clock)
	requiredCheck(t, err)
	analysis, err := analysishandler.NewHandler(store, clock)
	requiredCheck(t, err)
	memory, err := memoryhandler.NewHandler(store, clock, memorycore.NewLexicalIndex(), requiredDigest("memory-policy"), configuration.ReviewPolicyIdentity(), "reviewer", []string{"."}, 10, 20)
	requiredCheck(t, err)
	assembly, err := contexthandler.NewHandler(store, clock, generationAuthority)
	requiredCheck(t, err)
	generationHandler, err := modelhandler.NewGenerationHandler(store, dispatchers, ledger, clock)
	requiredCheck(t, err)
	verificationHandler, err := modelhandler.NewVerificationHandler(store, dispatchers, ledger, verificationAuthority, clock)
	requiredCheck(t, err)
	readiness, err := publicationhandler.NewReadinessHandler(store, diagnostics.NewMemoryStore(), clock, configuration.ReviewPolicyIdentity(), configuration.Publication())
	requiredCheck(t, err)
	publication, err := publicationhandler.NewHandler(store, clock, ledger, configuration.ReviewPolicyIdentity(), configuration.Publication(), effectAuthority, publishers, resolvers)
	requiredCheck(t, err)
	catalog, err := runtimecatalog.NewPipelineCatalog(controlplane.ReviewRunRequired, []controlplane.TaskHandler{sourceHandler, change, analysis, memory, assembly, generationHandler, verificationHandler, readiness, publication})
	requiredCheck(t, err)
	bindings := make([]githubwebhook.TaskHandlerBinding, 0, len(catalog.Bindings()))
	for _, binding := range catalog.Bindings() {
		bindings = append(bindings, githubwebhook.TaskHandlerBinding{Kind: binding.Kind, HandlerIdentity: binding.HandlerIdentity})
	}
	planner, err := githubwebhook.NewPreparedPullRequestPlanner("github.com", "owner/repository", configuration.ReviewPolicyIdentity(), publisher.PublisherID(), controlplane.ReviewRunRequired, bindings, adapterIdentity, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, time.Hour)
	requiredCheck(t, err)
	scope, err := webhook.NewRepositoryScope("tenant-a", "repo-a")
	requiredCheck(t, err)
	payload := []byte(`{"action":"synchronize","number":42,"repository":{"full_name":"owner/repository"},"pull_request":{"base":{"sha":"1111111111111111111111111111111111111111","repo":{"full_name":"owner/repository"}},"head":{"sha":"2222222222222222222222222222222222222222","repo":{"full_name":"owner/repository"}}}}`)
	delivery, err := webhook.NewVerifiedDelivery(scope, webhook.SourceGitHub, "delivery-required", "pull_request", "synchronize", requiredDigest("local-webhook-approval"), payload, clock.Now())
	requiredCheck(t, err)
	stored, _, err := webhook.NewMemoryStore().Put(ctx, delivery, clock.Now())
	requiredCheck(t, err)
	plan, inputs, err := planner.Prepare(ctx, stored)
	requiredCheck(t, err)
	if plan.TaskCount() != 10 || len(inputs) != 3 || catalog.Catalog().Len() != 9 || plan.Mode() != controlplane.ReviewRunRequired {
		t.Fatal("required pipeline did not include ten tasks and nine handler kinds")
	}
	for _, input := range inputs {
		_, err := store.Put(ctx, input, clock.Now())
		requiredCheck(t, err)
	}
	publisher.scope = plan.Scope()
	repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repository")
	requiredCheck(t, err)
	publisher.target, err = review.NewPublicationTarget(publisher.PublisherID(), repository, "42", head)
	requiredCheck(t, err)
	journal := controlplane.NewMemoryRunJournal()
	coordinator, err := controlplane.NewCoordinator(journal)
	requiredCheck(t, err)
	_, err = coordinator.Open(ctx, plan, clock.step())
	requiredCheck(t, err)
	return &requiredPipeline{t: t, clock: clock, store: store, ledger: ledger, journal: journal, coordinator: coordinator, plan: plan, catalog: catalog, configuration: configuration, source: source, generation: generation, verification: verification, publisher: publisher, requests: map[string]controlplane.TaskExecutionRequest{}, completions: map[string]controlplane.TaskCompletion{}}
}

func (f *requiredPipeline) run() controlplane.ReviewRunState {
	f.t.Helper()
	ctx := context.Background()
	finalizer, err := controlplane.NewRunFinalizer(f.journal)
	requiredCheck(f.t, err)
	for step := 0; step < f.plan.TaskCount(); step++ {
		state, err := f.coordinator.Advance(ctx, f.plan, f.clock.step())
		requiredCheck(f.t, err)
		var task controlplane.TaskDefinition
		for _, planned := range f.plan.Tasks() {
			runtime, ok := state.Task(planned.Key())
			if ok && runtime.Status() == controlplane.TaskRuntimeAvailable {
				task = planned
				break
			}
		}
		if task.Key() == "" {
			f.t.Fatal("pipeline stalled before terminal completion")
		}
		lease, acquired, err := f.coordinator.ClaimTask(ctx, f.plan, task.Key(), task.HandlerIdentity(), "local-worker", f.clock.step())
		requiredCheck(f.t, err)
		if !acquired {
			f.t.Fatalf("task %s lease not acquired", task.Key())
		}
		_, state, err = f.coordinator.Resume(ctx, f.plan.Scope())
		requiredCheck(f.t, err)
		dependencies, err := controlplane.TaskDependencyOutputsFromState(state, task)
		requiredCheck(f.t, err)
		request, err := controlplane.NewTaskExecutionRequestWithDependencies(f.plan, task, lease, dependencies)
		requiredCheck(f.t, err)
		f.requests[task.Key()] = request
		completion, err := controlplane.DispatchLeasedTask(ctx, f.catalog.Catalog(), state, lease, f.clock.step())
		requiredCheck(f.t, err)
		f.completions[task.Key()] = completion
		_, err = f.coordinator.CompleteTask(ctx, f.plan, lease, completion, f.clock.step())
		requiredCheck(f.t, err)
		state, terminal, err := finalizer.ReconcileRun(ctx, f.plan.Scope(), f.clock.step())
		requiredCheck(f.t, err)
		if terminal {
			return state
		}
	}
	f.t.Fatal("pipeline exceeded its bounded task count")
	return controlplane.ReviewRunState{}
}

func (f *requiredPipeline) output(state controlplane.ReviewRunState, key string) artifact.Artifact {
	f.t.Helper()
	task, ok := state.Task(key)
	if !ok || task.Status() != controlplane.TaskRuntimeSucceeded {
		f.t.Fatalf("task %s did not succeed: status=%s failure=%s", key, task.Status(), task.Failure())
	}
	value, err := f.store.Get(context.Background(), f.plan.Scope(), task.OutputIdentity(), f.clock.Now())
	requiredCheck(f.t, err)
	if value.Scope().Identity() != f.plan.Scope().Identity() || value.Classification() != artifact.ClassificationConfidential || value.Protection() != artifact.ProtectionProcessPrivate {
		f.t.Fatalf("task %s lost protected scope", key)
	}
	return value
}
