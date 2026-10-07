package runtimecatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func fullAdmissionPolicy(t *testing.T) (runtimeconfig.RuntimePolicy, runtimeconfig.RouteInventory) {
	t.Helper()
	capabilities, _ := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	price, _ := provider.NewRoutePricing(1000000, 1000000)
	definitions := make([]runtimeconfig.RouteDefinition, 2)
	for index, name := range []string{"a", "b"} {
		route, err := provider.NewRouteReference(provider.ProviderZoneLocal, "provider-"+name, "adapter-"+name, "connection-"+name, "model-"+name, "1")
		if err != nil {
			t.Fatal(err)
		}
		definitions[index] = runtimeconfig.RouteDefinition{Route: route, Capabilities: capabilities, ContentLogging: provider.ContentLoggingDisabled, Pricing: price, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: provider.RouteRegistryApproved, EvidenceManifest: []byte(`{"fixture":"local review route"}`), OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11, P95LatencyMilliseconds: 2500, LatencySampleCount: 100}
	}
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), definitions)
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		records[record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = record.Identity()
	}
	document, _ := json.Marshal(map[string]any{
		"schema_version": 1, "inventory_identity": inventory.Identity(), "review_policy_identity": strings.Repeat("e", 64),
		"min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"},
		"classification": "confidential", "allowed_zones": []string{"local"}, "content_logging_allowed": false,
		"estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": 1000000,
		"pinned_route_record_identity": records["adapter-a"], "preferred_route_record_identities": []string{records["adapter-b"]},
		"verification_independence": "distinct_provider", "publication_minimum_severity": "medium", "publication_max_inline_findings": 20,
		"publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true,
		"connections": []map[string]string{{"implementation": "openai_responses", "adapter_id": "adapter-a", "endpoint": "http://127.0.0.1:11434/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_A"}, {"implementation": "openai_responses", "adapter_id": "adapter-b", "endpoint": "http://127.0.0.1:11435/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_B"}},
	})
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(document), inventory)
	if err != nil {
		t.Fatal(err)
	}
	return policy, inventory
}

func fullAdmissionFixture(t *testing.T, runID string) (LocalFullReviewIntent, LocalFullReviewAdmissionConfig, controlplane.RunJournal, artifact.Store) {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", runID)
	repository, _ := evidence.NewRepositoryIdentity("local.test", []string{"team"}, "repository")
	base, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	head, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	adapter, _ := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "local-git-loose", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	policy, inventory := fullAdmissionPolicy(t)
	kinds := []controlplane.TaskKind{controlplane.TaskAcquireSource, controlplane.TaskBuildChange, controlplane.TaskInspectDeterministic, controlplane.TaskRetrieveContext, controlplane.TaskAssembleContext, controlplane.TaskGenerateCandidates, controlplane.TaskVerifyCandidates, controlplane.TaskEvaluatePublication}
	handlers := make([]controlplane.TaskHandler, len(kinds))
	for i, kind := range kinds {
		handlers[i] = handler{kind, strings.Repeat(string("12345678"[i]), 64)}
	}
	catalog, err := NewPipelineCatalog(controlplane.ReviewRunLocal, handlers)
	if err != nil {
		t.Fatal(err)
	}
	created := time.UnixMilli(1000)
	intent, err := NewLocalFullReviewIntent(scope, repository, base, head, policy.ReviewPolicyIdentity(), inventory.Identity(), policy.Identity(), created)
	if err != nil {
		t.Fatal(err)
	}
	config := LocalFullReviewAdmissionConfig{Source: fullAdmissionSourceStub{repository: repository.Identity(), valid: map[string]bool{base.Identity(): true, head.Identity(): true}}, Repository: repository, SourceAdapter: adapter, SourceRootIdentity: strings.Repeat("f", 64), Inventory: inventory, Policy: policy, Classification: artifact.ClassificationInternal, Protection: artifact.ProtectionProcessPrivate, Retention: 4 * time.Hour, Catalog: catalog}
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 128)
	return intent, config, controlplane.NewMemoryRunJournal(), store
}

func TestLocalFullAdmissionPersistsBoundNineTaskPlanAndDeduplicates(t *testing.T) {
	intent, config, journal, store := fullAdmissionFixture(t, "run-a")
	admitter, err := NewLocalFullReviewAdmitter(journal, store, config)
	if err != nil {
		t.Fatal(err)
	}
	state, err := admitter.Admit(context.Background(), intent, intent.CreatedAt().Add(time.Second))
	if err != nil || state.Status() != controlplane.ReviewRunActive {
		t.Fatalf("admission=(%#v,%v)", state, err)
	}
	plan, found, err := journal.LoadPlan(context.Background(), intent.Scope())
	if err != nil || !found || plan.TaskCount() != 9 || plan.PolicyIdentity() != config.Policy.ReviewPolicyIdentity() {
		t.Fatalf("plan=(%#v,%t,%v)", plan, found, err)
	}
	for _, key := range []string{"source-base", "source-head"} {
		task, _ := plan.Task(key)
		inputArtifact, readErr := store.Get(context.Background(), intent.Scope(), task.InputIdentity(), intent.CreatedAt().Add(time.Second))
		if readErr != nil {
			t.Fatal(readErr)
		}
		input, parseErr := sourcehandler.ParseInput(inputArtifact.Payload())
		if parseErr != nil || input.SourceRootIdentity() != config.SourceRootIdentity {
			t.Fatalf("source root=(%#v,%v)", input, parseErr)
		}
	}
	for _, key := range []string{"memory", "context", "candidates", "verification", "readiness"} {
		task, found := state.Task(key)
		if !found || task.Status() != controlplane.TaskRuntimePending {
			t.Fatalf("premature downstream task %q=(%#v,%t)", key, task, found)
		}
	}
	again, err := admitter.Admit(context.Background(), intent, intent.CreatedAt().Add(7*time.Minute))
	if err != nil || again.Plan().Identity() != plan.Identity() {
		t.Fatalf("replay=(%#v,%v)", again, err)
	}
	otherHead, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("3", 40))
	conflict, _ := NewLocalFullReviewIntent(intent.Scope(), intent.Repository(), intent.BaseRevision(), otherHead, intent.ReviewPolicyIdentity(), intent.InventoryIdentity(), intent.RuntimePolicyIdentity(), intent.CreatedAt())
	if _, err := admitter.Admit(context.Background(), conflict, intent.CreatedAt().Add(2*time.Second)); !errors.Is(err, ErrLocalFullReviewConflict) {
		t.Fatalf("conflict=%v", err)
	}
}

type fullAdmissionSourceStub struct {
	repository string
	valid      map[string]bool
	failure    error
}

func (s fullAdmissionSourceStub) RepositoryIdentity() string { return s.repository }
func (s fullAdmissionSourceStub) ValidateLocalRevision(_ context.Context, revision evidence.RevisionIdentity) error {
	if s.failure != nil {
		return s.failure
	}
	if !s.valid[revision.Identity()] {
		return fmt.Errorf("revision unavailable")
	}
	return nil
}

func TestLocalFullAdmissionRejectsInvalidSourceAndPolicyBeforeOpening(t *testing.T) {
	intent, config, journal, store := fullAdmissionFixture(t, "run-invalid")
	admitter, err := NewLocalFullReviewAdmitter(journal, store, config)
	if err != nil {
		t.Fatal(err)
	}
	otherHead, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("9", 40))
	missing, _ := NewLocalFullReviewIntent(intent.Scope(), intent.Repository(), intent.BaseRevision(), otherHead, intent.ReviewPolicyIdentity(), intent.InventoryIdentity(), intent.RuntimePolicyIdentity(), intent.CreatedAt())
	if _, err := admitter.Admit(context.Background(), missing, intent.CreatedAt().Add(time.Second)); !errors.Is(err, ErrInvalidLocalFullReview) {
		t.Fatalf("missing revision=%v", err)
	}
	changedPolicy, _ := NewLocalFullReviewIntent(intent.Scope(), intent.Repository(), intent.BaseRevision(), intent.HeadRevision(), strings.Repeat("a", 64), intent.InventoryIdentity(), intent.RuntimePolicyIdentity(), intent.CreatedAt())
	if _, err := admitter.Admit(context.Background(), changedPolicy, intent.CreatedAt().Add(time.Second)); !errors.Is(err, ErrInvalidLocalFullReview) {
		t.Fatalf("policy mismatch=%v", err)
	}
	if _, found, err := journal.LoadPlan(context.Background(), intent.Scope()); err != nil || found {
		t.Fatalf("invalid request opened plan: found=%t err=%v", found, err)
	}
	stale, _ := NewLocalFullReviewIntent(intent.Scope(), intent.Repository(), intent.BaseRevision(), intent.HeadRevision(), intent.ReviewPolicyIdentity(), intent.InventoryIdentity(), intent.RuntimePolicyIdentity(), intent.CreatedAt())
	if _, err := admitter.Admit(context.Background(), stale, intent.CreatedAt().Add(6*time.Minute)); !errors.Is(err, ErrLocalFullReviewExpired) {
		t.Fatalf("stale=%v", err)
	}
}

func TestLocalFullAdmissionKeepsSourceResourceFailureSeparate(t *testing.T) {
	intent, config, journal, store := fullAdmissionFixture(t, "run-resource")
	source := config.Source.(fullAdmissionSourceStub)
	source.failure = scm.LocalGitRevisionResourceLimit
	config.Source = source
	admitter, err := NewLocalFullReviewAdmitter(journal, store, config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = admitter.Admit(context.Background(), intent, intent.CreatedAt().Add(time.Second))
	if !errors.Is(err, scm.LocalGitRevisionResourceLimit) {
		t.Fatalf("source resource error reclassified: %v", err)
	}
	if _, found, loadErr := journal.LoadPlan(context.Background(), intent.Scope()); loadErr != nil || found {
		t.Fatalf("resource error opened plan: found=%t err=%v", found, loadErr)
	}
}
