package runtimecatalog_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const goCallerReasoningSentinel = "DO_NOT_PERSIST_REASONING_SENTINEL"
const goCallerCandidateContent = `{"schema_version":2,"candidates":[]}`

type goCallerStore struct {
	artifact.Store
	t *testing.T
}

func (s goCallerStore) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	if bytes.Contains(value.Payload(), []byte(goCallerReasoningSentinel)) {
		s.t.Fatal("reasoning reached actual artifact store Put")
	}
	return s.Store.Put(ctx, value, at)
}

type goCallerTransport struct {
	t             *testing.T
	scope         audit.ReviewScope
	authorization gateway.RouteAttemptAuthorization
	ledger        audit.Ledger
	calls         int
	sessions      []string
	requests      []string
}

func (r *goCallerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	r.calls++
	if request.URL.String() != "https://opencode.ai/inference/go/openai/v1/chat/completions" || request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer synthetic-go-key" || request.Header.Get("User-Agent") != "open-trestle/1" || request.Header.Get("Accept") != "application/json" || request.Header.Get("Content-Type") != "application/json" {
		r.t.Fatal("Go target or headers not bound")
	}
	session := request.Header.Get("x-opencode-session")
	if len(session) != 72 || session != "trestle_"+requiredDigest("open-trestle/opencode-go-session/v1/"+r.scope.Identity()) {
		r.t.Fatal("Go session is not the host-authorized scope commitment")
	}
	if r.authorization.Validate() != nil || r.authorization.ReviewScopeIdentity() != r.scope.Identity() || r.authorization.ReservedCostMicroUSD() == 0 || r.authorization.MaxOutputTokens() != 4096 {
		r.t.Fatal("HTTP reached without the expected bounded authorization")
	}
	events, err := r.ledger.Read(request.Context(), r.scope, 0, 20)
	requiredCheck(r.t, err)
	if len(events) == 0 || events[len(events)-1].Kind() != audit.EventRouteAttemptClaimed || events[len(events)-1].SubjectIdentity() != r.authorization.Identity() {
		r.t.Fatal("HTTP occurred before the actual authorization claim")
	}
	defer request.Body.Close()
	body, err := io.ReadAll(io.LimitReader(request.Body, (8<<20)+1))
	requiredCheck(r.t, err)
	if len(body) == 0 || len(body) > 8<<20 {
		r.t.Fatal("Go request bound")
	}
	var wire struct {
		Model     string                           `json:"model"`
		Messages  []struct{ Role, Content string } `json:"messages"`
		MaxTokens uint32                           `json:"max_tokens"`
		Stream    bool                             `json:"stream"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	requiredCheck(r.t, decoder.Decode(&wire))
	if decoder.Decode(&struct{}{}) != io.EOF || wire.Model != "glm-5.3-flash" || wire.MaxTokens != r.authorization.MaxOutputTokens() || wire.Stream || len(wire.Messages) != 2 || wire.Messages[0].Role != "system" || wire.Messages[1].Role != "user" {
		r.t.Fatal("Go request protocol or role changed")
	}
	payload := []byte(wire.Messages[1].Content)
	instructions, err := review.TrustedModelRequestInstructions(payload)
	requiredCheck(r.t, err)
	if instructions != wire.Messages[0].Content {
		r.t.Fatal("trusted instruction bytes changed")
	}
	neutral, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", payload)
	requiredCheck(r.t, err)
	if review.ValidateCandidateModelRequest(neutral, r.scope.Identity()) != nil {
		r.t.Fatal("Go transport did not receive scoped sanitized candidate context")
	}
	r.sessions = append(r.sessions, session)
	r.requests = append(r.requests, r.authorization.RequestIdentity())
	response := `{"id":"go-fixture","object":"chat.completion","model":"glm-5.3-flash","choices":[{"index":0,"message":{"role":"assistant","content":"{\"schema_version\":2,\"candidates\":[]}","reasoning_content":"DO_NOT_PERSIST_REASONING_SENTINEL"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1200,"completion_tokens":300,"cost":0,"opencode":{"billing_source":"go","list_cost":0.001,"allowance":0.001,"tokens":{"input":1200,"output":300,"reasoning":120,"cache_read":8000,"cache_write_5m":0,"cache_write_1h":0}}}}`
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(response)), Request: request}, nil
}

func goCallerRuntimePolicy(t *testing.T) (runtimeconfig.RuntimePolicy, runtimeconfig.RouteInventory) {
	t.Helper()
	ctx := context.Background()
	marshal := func(value any) []byte { encoded, err := json.Marshal(value); requiredCheck(t, err); return encoded }
	type source struct {
		URL           string `json:"url"`
		RetrievedAt   string `json:"retrieved_at"`
		ContentSHA256 string `json:"content_sha256"`
	}
	account := struct {
		AuthorityLabel              string `json:"authority_label"`
		CredentialReferenceIdentity string `json:"credential_reference_identity"`
		Subscription                string `json:"subscription"`
		WorkspaceMembership         string `json:"workspace_membership"`
		PrivacyTraining             string `json:"privacy_training"`
		ExtraUsage                  string `json:"extra_usage"`
		ReviewEvidence              source `json:"review_evidence"`
	}{"synthetic Go single-member account, not live approval", requiredDigest("open-trestle/provider-credential-environment/OPEN_TRESTLE_PROVIDER_OPENCODE_GO"), "go", "single_member", "disabled", "disabled", source{"https://account-review.fixture.invalid/go/privacy-and-extra-usage", "2026-10-29T00:00:00Z", requiredDigest("synthetic account privacy and Extra Usage off review")}}
	accountPreimage := struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Account  any    `json:"account"`
	}{"open-trestle/opencode-go-account-policy", 1, account}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(`{"opencode_go_privacy":{"contract":"open-trestle/opencode-go-privacy-witness","schema_version":1,"route":{"zone":"brokered_remote","provider_id":"opencode-go","adapter_id":"adapter-a","connection_id":"primary/opencode-go","model_id":"glm-5.3-flash","model_version":"","effective_selector":"glm-5.3-flash"},"endpoint":"https://opencode.ai/inference/go/openai/v1","request_profile":"opencode_go_chat_v1","protocol":"openai_chat_completions","credential_mode":"bearer","model_privacy":{"training":"disabled","retention_days":0},"broker_privacy":{"retention_contract":"model_specific_documented_zero_days"},"tenant_id":"tenant-a","repository_id":"repository-a","reviewed_at":"2026-10-29T00:00:00Z","valid_from":"2026-10-29T00:00:00Z","valid_until":"2026-11-01T00:00:00Z","byok":"excluded","tools":"excluded","plugins":"excluded","streaming":"excluded","client":{"user_agent":"open-trestle/1","session_derivation":"authorized_review_scope_sha256_v1"}}}`), &manifest); err != nil {
		t.Fatal(err)
	}
	witness := manifest["opencode_go_privacy"].(map[string]any)
	witness["account"] = account
	witness["model_privacy"].(map[string]any)["evidence"] = source{"https://evidence.fixture.invalid/go/glm-5.3-flash-privacy", "2026-10-29T00:00:00Z", requiredDigest("synthetic documented exact model zero-day no-training review")}
	witness["broker_privacy"].(map[string]any)["evidence"] = source{"https://evidence.fixture.invalid/go/broker-privacy-scope", "2026-10-29T00:00:00Z", requiredDigest("synthetic broker privacy scope review")}
	caps, err := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	requiredCheck(t, err)
	price, err := provider.NewRoutePricing(150000, 500000)
	requiredCheck(t, err)
	definitions := make([]runtimeconfig.RouteDefinition, 0, 2)
	for index, id := range []string{"adapter-a", "verifier"} {
		zone, providerID, connection, model := provider.ProviderZoneBrokeredRemote, "opencode-go", "primary/opencode-go", "glm-5.3-flash"
		evidence := marshal(manifest)
		if index == 1 {
			zone, providerID, connection, model = provider.ProviderZonePrivateRemote, "direct", "primary/direct", "verifier"
			evidence = []byte(`{"fixture":"synthetic direct verifier evidence"}`)
		}
		route, err := provider.NewRouteReference(zone, providerID, id, connection, model, "")
		requiredCheck(t, err)
		definitions = append(definitions, runtimeconfig.RouteDefinition{Route: route, Capabilities: caps, ContentLogging: provider.ContentLoggingDisabled, Pricing: price, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: provider.RouteRegistryApproved, EvidenceManifest: evidence, OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11})
	}
	inventory, err := runtimeconfig.NewRouteInventory(ctx, definitions)
	requiredCheck(t, err)
	requiredCheck(t, inventory.Validate())
	var generation, verifier, evidence string
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		if record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "adapter-a" {
			generation, evidence = record.Identity(), record.EvidenceManifestDigest()
		} else {
			verifier = record.Identity()
		}
	}
	wire := map[string]any{
		"schema_version": 4, "inventory_identity": inventory.Identity(), "review_policy_identity": requiredDigest("go-review-policy"),
		"min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{"brokered_remote", "private_remote"}, "content_logging_allowed": false,
		"estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": 1000000, "pinned_route_record_identity": generation, "preferred_route_record_identities": []string{}, "verification_route_record_identity": verifier, "verification_independence": "distinct_provider",
		"publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true,
		"connections": []any{
			map[string]any{"implementation": "openai_chat_completions", "adapter_id": "adapter-a", "endpoint": "https://opencode.ai/inference/go/openai/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_OPENCODE_GO", "request_profile": "opencode_go_chat_v1", "opencode_go_authority": map[string]any{"route_record_identity": generation, "evidence_manifest_digest": evidence, "account_policy_identity": requiredDigest(string(marshal(accountPreimage))), "tenant_id": "tenant-a", "repository_id": "repository-a", "valid_from": "2026-10-29T00:00:00Z", "valid_until": "2026-11-01T00:00:00Z"}},
			map[string]any{"implementation": "openai_responses", "adapter_id": "verifier", "endpoint": "https://direct.example/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_DIRECT"},
		},
	}
	configuration, err := runtimeconfig.DecodeRuntimePolicy(ctx, bytes.NewReader(marshal(wire)), inventory)
	if err != nil {
		t.Fatalf("Go common-caller v4 policy refused before catalog: %v", err)
	}
	requiredCheck(t, configuration.ValidateAgainstInventory(inventory))
	return configuration, inventory
}

func TestCommonRuntimePolicyCatalogOpenCodeGoUsesGenerationHandler(t *testing.T) {
	ctx := context.Background()
	clock := &requiredClock{at: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	configuration, inventory := goCallerRuntimePolicy(t)
	key, err := openai.NewAPIKey([]byte("synthetic-go-key"))
	requiredCheck(t, err)
	credentials := &brokeredCountingCredentials{key: key}
	transport := &goCallerTransport{t: t}
	catalog, err := runtimecatalog.NewOpenAIRouteDispatcherCatalogWithOptions(inventory, configuration, brokeredResolver{credentials}, runtimecatalog.OpenAICatalogOptions{Clock: clock, HTTPClient: &http.Client{Transport: transport, Timeout: 2 * time.Minute}, HTTPClientIdentity: requiredDigest("go-recording-http")})
	requiredCheck(t, err)
	memoryStore, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	requiredCheck(t, err)
	store := goCallerStore{Store: memoryStore, t: t}
	ledger := audit.NewMemoryLedger()
	transport.ledger = ledger
	sanitizer := testsupport.NewCleanGenerationSanitizer()
	handler, err := modelhandler.NewGenerationHandler(store, catalog, ledger, clock, sanitizer.ExpectedBinaryDigests())
	requiredCheck(t, err)
	usage, err := provider.NewRouteTokenUsage(1200, 300, 0)
	requiredCheck(t, err)
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(goCallerCandidateContent))
	requiredCheck(t, err)
	expectedResponse, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	requiredCheck(t, err)
	var previousAuthorization, previousRequest string
	for index, run := range []string{"go-run-a", "go-run-a", "go-run-b"} {
		clock.at = clock.at.Add(time.Second)
		scope, err := audit.NewReviewScope("tenant-a", "repository-a", run)
		requiredCheck(t, err)
		request := brokeredGenerationRequest(t, scope, clock, configuration, inventory, store, ledger, handler)
		dependency, ok := request.DependencyOutput("context")
		if !ok || !dependency.Available() {
			t.Fatal("generation task lost its actual input dependency")
		}
		inputArtifact, err := store.Get(ctx, scope, dependency.OutputIdentity(), clock.Now())
		requiredCheck(t, err)
		input, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
		requiredCheck(t, err)
		authorization := input.Authorization()
		if index == 1 && (authorization.Identity() == previousAuthorization || authorization.RequestIdentity() == previousRequest) {
			t.Fatal("same-scope oracle replayed an already claimed request instead of creating fresh authorized input")
		}
		transport.scope, transport.authorization = scope, authorization
		completion := handler.Execute(ctx, request)
		if completion.Validate() != nil || completion.Status() != controlplane.TaskCompletionSucceeded {
			t.Fatalf("Go generation failed: %#v", completion)
		}
		output, err := store.Get(ctx, scope, completion.OutputIdentity(), clock.Now())
		requiredCheck(t, err)
		contextArtifact, err := store.Get(ctx, scope, input.ContextArtifactIdentity(), clock.Now())
		requiredCheck(t, err)
		result, err := modelhandler.ParseGenerationResultArtifact(output, inputArtifact, contextArtifact)
		requiredCheck(t, err)
		if result.Validate() != nil || len(result.Candidates().Findings()) != 0 {
			t.Fatal("Go caller did not admit the expected typed empty candidate batch")
		}
		execution := result.RouteExecution()
		if execution.Validate() != nil || execution.Authorization().Identity() != authorization.Identity() || execution.Outcome().AuthorizationIdentity() != authorization.Identity() || execution.Outcome().ResponseIdentity() != expectedResponse.Identity() || result.Candidates().ResponseIdentity() != expectedResponse.Identity() {
			t.Fatal("Go response/content/usage lineage changed or retained reasoning")
		}
		observed := execution.Outcome().Usage()
		if !observed.IsKnown() || observed.InputTokens() != 1200 || observed.OutputTokens() != 300 || observed.CachedInputTokens() != 0 {
			t.Fatal("native usage replaced by billed/cache counts or unknown")
		}
		reconciliation := execution.Reconciliation()
		actual, err := provider.CalculateActualRouteCost(authorization.Pricing(), usage)
		requiredCheck(t, err)
		if reconciliation.Validate() != nil || !reconciliation.ActualCost().IsKnown() || reconciliation.ActualCost().TotalCostMicroUSD() != actual.TotalCostMicroUSD() || reconciliation.ReservedCostMicroUSD() != authorization.ReservedCostMicroUSD() || reconciliation.Status() != gateway.RouteCostWithinReservation || authorization.ReservedCostMicroUSD() == 0 {
			t.Fatal("Go handler skipped real fixed-price reservation/reconciliation")
		}
		if bytes.Contains(output.Payload(), []byte(goCallerReasoningSentinel)) {
			t.Fatal("reasoning persisted in candidate result")
		}
		events, err := ledger.Read(ctx, scope, 0, 20)
		requiredCheck(t, err)
		expectedAttempts := 1
		if index == 1 {
			expectedAttempts = 2
		}
		if len(events) != expectedAttempts*4 {
			t.Fatal("unexpected handler audit count or implicit retry/fallback")
		}
		for offset := 0; offset < len(events); offset += 4 {
			kinds := []audit.EventKind{audit.EventRouteSelected, audit.EventRouteAttemptClaimed, audit.EventRouteDispatchCompleted, audit.EventRouteCostReconciled}
			for n, kind := range kinds {
				event := events[offset+n]
				if event.Validate() != nil || event.Kind() != kind {
					t.Fatal("actual selection/claim/dispatch/reconciliation audit lineage missing")
				}
				encoded, err := audit.EncodeEvent(event)
				requiredCheck(t, err)
				if bytes.Contains(encoded, []byte(goCallerReasoningSentinel)) {
					t.Fatal("reasoning persisted in audit")
				}
			}
		}
		if events[len(events)-3].SubjectIdentity() != authorization.Identity() {
			t.Fatal("new authorization was not actually claimed")
		}
		if index == 1 && events[1].SubjectIdentity() == events[5].SubjectIdentity() {
			t.Fatal("same-scope request reused prior authorization claim")
		}
		if events[len(events)-2].SubjectIdentity() != execution.Outcome().Identity() || events[len(events)-1].SubjectIdentity() != reconciliation.Identity() {
			t.Fatal("audit subjects not linked to actual route execution")
		}
		if transport.calls != index+1 || credentials.calls != index+1 {
			t.Fatal("Go handler added hidden calls/retries")
		}
		previousAuthorization, previousRequest = authorization.Identity(), authorization.RequestIdentity()
	}
	if len(transport.sessions) != 3 || transport.sessions[0] != transport.sessions[1] || transport.sessions[0] == transport.sessions[2] || transport.requests[0] == transport.requests[1] {
		t.Fatal("Go session/request scope relationship changed")
	}
}
