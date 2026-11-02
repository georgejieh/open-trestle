package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// TestPlanAndGrantProducesV5TaskInput proves the end-to-end call chain:
// PlanLocalGenerationRoute → GrantLocalGenerationRoute → BuildAuthorizedPacketInput
// produces a real artifact.KindTaskInput from a real local route grant and real
// packet candidate, with a selection audit event written to the ledger.
//
// The test uses the localPacketOwnerFixture for the packet candidate chain and
// the same route definitions as the local generation authority tests.
// No source or provider contact occurs.
func TestPlanAndGrantProducesV5TaskInput(t *testing.T) {
	fixture := newLocalPacketOwnerFixture(t)
	ctx, scope, at := context.Background(), fixture.request.Plan().Scope(), fixture.clock.Now()

	// Verify the fixture is in the right state for the context task.
	_, state, err := fixture.coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	runtime, ok := state.Task("context")
	if !ok || runtime.Status() != controlplane.TaskRuntimeLeased {
		t.Fatal("fixture context task is not leased")
	}

	// --- Build packet candidate from the real fixture store ---
	candidate, err := contexthandler.BuildPacketCandidate(
		ctx, localPacketFixtureReader{fixture.store}, fixture.request, state,
		fixture.clock, fixture.rootDigest, at, at,
	)
	if err != nil {
		t.Fatal(err)
	}

	// --- Sanitize using the clean sanitizer (no model contact) ---
	sanitized, err := contexthandler.BuildSanitizedPacketCandidate(
		ctx, candidate, testsupport.NewCleanGenerationSanitizer(), at,
	)
	if err != nil {
		t.Fatal(err)
	}
	modelRequest, err := sanitized.Request()
	if err != nil {
		t.Fatal(err)
	}

	// --- Build inventory and policy matching the local generation authority fixtures ---
	inventory, policy, err := localGenerationInventoryAndPolicyForTest(ctx, t)
	if err != nil {
		t.Fatal(err)
	}

	// --- Resolve the route pair from the policy and inventory ---
	pair, err := runtimecatalog.ResolveLocalGenerationRoutePair(policy, inventory)
	if err != nil {
		t.Fatalf("ResolveLocalGenerationRoutePair failed: %v", err)
	}
	if err := pair.Validate(); err != nil {
		t.Fatal(err)
	}

	// --- Plan: proves the actual sanitized request fits the bound generation record.
	// Plan.authorization is private; we verify via the grant's exported methods.
	plan, err := runtimecatalog.PlanLocalGenerationRoute(ctx, scope, modelRequest, policy, inventory, pair)
	if err != nil {
		t.Fatalf("PlanLocalGenerationRoute failed: %v", err)
	}
	if plan.SelectionIdentity() == "" {
		t.Fatal("plan has empty selection identity")
	}
	if plan.SelectedRecordIdentity() != pair.GenerationRecordIdentity() {
		t.Fatal("plan selected record differs from pair generation record")
	}
	if plan.RequestIdentity() != modelRequest.Identity() {
		t.Fatal("plan request identity differs from model request")
	}
	if plan.PolicyIdentity() != policy.Identity() {
		t.Fatal("plan policy identity differs from policy")
	}

	// --- Grant: proves the same request still produces the identical plan, then records selection.
	// GrantLocalGenerationRoute calls PlanLocalGenerationRoute again internally and compares
	// with reflect.DeepEqual.  A non-zero grant identity proves the deep-equal passed.
	ledger := audit.NewMemoryLedger()
	grant, err := runtimecatalog.GrantLocalGenerationRoute(ctx, scope, modelRequest, policy, inventory, pair, plan, ledger, at)
	if err != nil {
		t.Fatalf("GrantLocalGenerationRoute failed: %v", err)
	}
	if err := grant.Validate(); err != nil {
		t.Fatal("granted authorization is invalid")
	}
	// A non-empty grant identity proves the second PlanLocalGenerationRoute call
	// inside GrantLocalGenerationRoute produced a deep-equal plan and a valid authorization.
	if grant.Identity() == "" {
		t.Fatal("grant has empty identity")
	}
	if grant.RequestIdentity() != modelRequest.Identity() {
		t.Fatal("grant does not bind the actual request")
	}
	if grant.RouteRecordIdentity() != pair.GenerationRecordIdentity() {
		t.Fatal("grant route record differs from pair generation record")
	}

	// --- Selection audit event proves the ledger was written ---
	events, err := ledger.Read(ctx, scope, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 ledger event, got %d", len(events))
	}
	if events[0].Kind() != audit.EventRouteSelected {
		t.Fatalf("expected EventRouteSelected, got %v", events[0].Kind())
	}
	if events[0].SubjectIdentity() != plan.SelectionIdentity() {
		t.Fatalf("selection subject=%q != plan selection=%q", events[0].SubjectIdentity(), plan.SelectionIdentity())
	}

	// --- Build authorized input: proves BuildAuthorizedPacketInput accepts the real grant ---
	input, err := contexthandler.BuildAuthorizedPacketInput(
		ctx, sanitized, grant, fixture.request, strings.Repeat("e", 64), at,
	)
	if err != nil {
		t.Fatalf("BuildAuthorizedPacketInput failed: %v", err)
	}

	// --- Verify the result is a real v5 task_input ---
	if input.Kind() != artifact.KindTaskInput {
		t.Fatalf("expected KindTaskInput, got %v", input.Kind())
	}
	if err := input.Validate(); err != nil {
		t.Fatal("task input artifact failed validation")
	}
	if input.Identity() == "" {
		t.Fatal("task input has empty identity")
	}

	// --- Parse and verify full lineage ---
	parsed, err := modelhandler.ParseGenerationInput(input.Payload())
	if err != nil {
		t.Fatalf("ParseGenerationInput failed: %v", err)
	}
	if !parsed.IsSanitized() {
		t.Fatal("parsed input is not sanitized")
	}
	if parsed.Authorization().Identity() != grant.Identity() {
		t.Fatal("parsed authorization identity differs from grant")
	}
	if parsed.ContextArtifactIdentity() != candidate.Artifact().Identity() {
		t.Fatal("parsed context artifact identity differs from candidate")
	}
	if parsed.SanitizedRequestArtifactIdentity() != sanitized.RequestArtifact().Identity() {
		t.Fatal("parsed request artifact identity differs from sanitized request artifact")
	}
	if parsed.SanitizedEgressReceiptArtifactIdentity() != sanitized.ReceiptArtifact().Identity() {
		t.Fatal("parsed receipt artifact identity differs from sanitized receipt artifact")
	}

	// --- Verify provenance binds all required parents ---
	analysis, _ := fixture.request.DependencyOutput("analysis")
	memory, _ := fixture.request.DependencyOutput("memory")
	wantProvenance := []string{
		analysis.OutputIdentity(), memory.OutputIdentity(),
		fixture.request.Plan().PolicyIdentity(), strings.Repeat("e", 64),
		candidate.Artifact().Identity(), grant.Identity(),
		sanitized.RequestArtifact().Identity(), sanitized.ReceiptArtifact().Identity(),
	}
	sortedWant := make([]string, len(wantProvenance))
	copy(sortedWant, wantProvenance)
	sort.Strings(sortedWant)
	got := input.Provenance()
	sortedGot := make([]string, len(got))
	copy(sortedGot, got)
	sort.Strings(sortedGot)
	if !reflect.DeepEqual(sortedGot, sortedWant) {
		t.Fatalf("provenance mismatch:\ngot:  %v\nwant: %v", sortedGot, sortedWant)
	}

	// --- Verify no artifact was persisted to the store and no journal event was appended ---
	beforeEvents, err := fixture.journal.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Get(ctx, scope, input.Identity(), at); err == nil {
		t.Fatal("task input was persisted to store")
	}
	afterEvents, err := fixture.journal.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeEvents, afterEvents) {
		t.Fatal("journal was modified by buildAuthorizedPacketInput")
	}
	preparedPacket, err := fixture.owner.PreparePacket(ctx, fixture.request)
	if err != nil {
		t.Fatalf("real packet owner preparation: %v", err)
	}
	descriptor, err := buildLocalContextInputDescriptor(preparedPacket, fixture.request.Lease(), sanitized, input, grant, plan, strings.Repeat("e", 64))
	if err != nil {
		t.Fatalf("real descriptor: %v", err)
	}
	if descriptor.PacketPreparedEventIdentity != preparedPacket.Identity() || descriptor.Input.ArtifactIdentity != input.Identity() || descriptor.SelectionReceiptIdentity != plan.SelectionIdentity() {
		t.Fatal("descriptor does not bind packet, task_input and audited route selection")
	}
	preparedInput, err := fixture.coordinator.PrepareContextInput(ctx, fixture.request.Plan(), fixture.request.Lease(), preparedPacket, descriptor, at.Add(time.Millisecond))
	if err != nil || preparedInput.Descriptor().Input.ArtifactIdentity != input.Identity() {
		t.Fatalf("real v5 intent: %v", err)
	}
}

// localGenerationInventoryAndPolicyForTest builds a RouteInventory and RuntimePolicy
// that match the route definitions used by the local generation authority tests.
// Both generation and verification routes are ProviderZoneLocal, matching the
// contract required by ResolveLocalGenerationRoutePair.
func localGenerationInventoryAndPolicyForTest(ctx context.Context, t *testing.T) (runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy, error) {
	return localGenerationInventoryAndPolicyWithReviewPolicyForTest(ctx, t, strings.Repeat("e", 64))
}

func localGenerationInventoryAndPolicyWithReviewPolicyForTest(ctx context.Context, t *testing.T, reviewPolicyIdentity string) (runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy, error) {
	t.Helper()
	capabilities, err := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	if err != nil {
		return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, err
	}
	price, err := provider.NewRoutePricing(1000000, 1000000)
	if err != nil {
		return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, err
	}
	definitions := make([]runtimeconfig.RouteDefinition, 2)
	for i, name := range []string{"a", "b"} {
		routeRef, err := provider.NewRouteReference(
			provider.ProviderZoneLocal,
			"provider-"+name, "adapter-"+name,
			"connection-"+name, "model-"+name, "1",
		)
		if err != nil {
			return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, err
		}
		definitions[i] = runtimeconfig.RouteDefinition{
			Route:                  routeRef,
			Capabilities:           capabilities,
			ContentLogging:         provider.ContentLoggingDisabled,
			Pricing:                price,
			Quality:                provider.RouteQualityTier3,
			RegistryRevision:       7,
			RegistryStatus:         provider.RouteRegistryApproved,
			EvidenceManifest:       []byte(`{"fixture":"local review route"}`),
			OperationalRevision:    9,
			Health:                 provider.RouteHealthHealthy,
			Quota:                  provider.RouteQuotaAvailable,
			PerformanceRevision:    11,
			P95LatencyMilliseconds: 2500,
			LatencySampleCount:     100,
		}
	}
	inventory, err := runtimeconfig.NewRouteInventory(ctx, definitions)
	if err != nil {
		return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, err
	}
	// Map adapter IDs to record identities in inventory iteration order.
	records := make(map[string]string)
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		ref := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		if _, ok := records[ref.AdapterID()]; !ok {
			records[ref.AdapterID()] = record.Identity()
		}
	}
	doc := map[string]any{
		"schema_version":                     2,
		"verification_route_record_identity": records["adapter-b"],
		"inventory_identity":                 inventory.Identity(),
		"review_policy_identity":             reviewPolicyIdentity,
		"min_context_tokens":                 32000,
		"min_output_tokens":                  4096,
		"required_features":                  []string{"structured_output"},
		"classification":                     "confidential",
		"allowed_zones":                      []string{"local"},
		"content_logging_allowed":            false,
		"estimated_input_tokens":             1000,
		"max_output_tokens":                  4096,
		"max_cost_micro_usd":                 1000000,
		"pinned_route_record_identity":       records["adapter-a"],
		"preferred_route_record_identities":  []string{},
		"verification_independence":          "distinct_provider",
		"publication_minimum_severity":       "medium",
		"publication_max_inline_findings":    20,
		"publication_minimum_independence":   "distinct_provider",
		"publication_block_on_inconclusive":  true,
		"connections": []map[string]string{
			{"implementation": "openai_responses", "adapter_id": "adapter-a", "endpoint": "http://127.0.0.1:11434/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_A"},
			{"implementation": "openai_responses", "adapter_id": "adapter-b", "endpoint": "http://127.0.0.1:11435/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_FIXTURE_B"},
		},
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, err
	}
	policy, err := runtimeconfig.DecodeRuntimePolicy(ctx, bytes.NewReader(encoded), inventory)
	if err != nil {
		return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, err
	}
	return inventory, policy, nil
}
