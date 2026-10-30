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

const ollamaCloudCandidateContent = `{"schema_version":1,"candidates":[]}`

type ollamaCloudCredentials struct {
	t             *testing.T
	delegate      *brokeredCountingCredentials
	ledger        audit.Ledger
	scope         audit.ReviewScope
	authorization gateway.RouteAttemptAuthorization
}

func (p *ollamaCloudCredentials) Retrieve(ctx context.Context) (openai.APIKey, error) {
	events, err := p.ledger.Read(ctx, p.scope, 0, 20)
	if err != nil {
		return openai.APIKey{}, err
	}
	if p.authorization.Validate() != nil || len(events) != 2 || events[1].Kind() != audit.EventRouteAttemptClaimed || events[1].SubjectIdentity() != p.authorization.Identity() {
		p.t.Fatal("Ollama key retrieval preceded actual authorization claim")
	}
	return p.delegate.Retrieve(ctx)
}

type ollamaCloudResolver struct{ credentials openai.APIKeyProvider }

func (r ollamaCloudResolver) ResolveOpenAICredentials(string) (openai.APIKeyProvider, error) {
	return r.credentials, nil
}

type ollamaCloudTransport struct {
	t             *testing.T
	ledger        audit.Ledger
	scope         audit.ReviewScope
	authorization gateway.RouteAttemptAuthorization
	payload       []byte
	instructions  string
	responseModel string
	calls         int
}

func (r *ollamaCloudTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	r.calls++
	if request.Method != http.MethodPost || request.URL.String() != "https://ollama.com/v1/chat/completions" || request.URL.User != nil || request.Header.Get("Authorization") != "Bearer synthetic-ollama-key" || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" || request.Header.Get("Cookie") != "" || request.Header.Get("x-opencode-session") != "" {
		r.t.Fatal("unbound Ollama direct target/auth")
	}
	if r.authorization.Validate() != nil || r.authorization.ReviewScopeIdentity() != r.scope.Identity() || r.authorization.ReservedCostMicroUSD() == 0 {
		r.t.Fatal("Ollama request lacks bounded authorization")
	}
	events, err := r.ledger.Read(request.Context(), r.scope, 0, 20)
	requiredCheck(r.t, err)
	if len(events) != 2 || events[1].Kind() != audit.EventRouteAttemptClaimed || events[1].SubjectIdentity() != r.authorization.Identity() {
		r.t.Fatal("Ollama HTTP preceded actual claim")
	}
	defer request.Body.Close()
	body, err := io.ReadAll(io.LimitReader(request.Body, (8<<20)+1))
	requiredCheck(r.t, err)
	if len(body) == 0 || len(body) > 8<<20 {
		r.t.Fatal("Ollama request bound")
	}
	var members map[string]json.RawMessage
	requiredCheck(r.t, json.Unmarshal(body, &members))
	if len(members) != 4 || !bytes.Equal(members["stream"], []byte("false")) {
		r.t.Fatal("unexpected Ollama request extension or stream")
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
	if decoder.Decode(&struct{}{}) != io.EOF || wire.Model != "gemma4:31b" || wire.MaxTokens != r.authorization.MaxOutputTokens() || wire.MaxTokens != 4096 || wire.Stream || len(wire.Messages) != 2 || wire.Messages[0].Role != "system" || wire.Messages[1].Role != "user" || wire.Messages[0].Content != r.instructions || !bytes.Equal([]byte(wire.Messages[1].Content), r.payload) {
		r.t.Fatal("Ollama selector, authorized limit or trusted body changed")
	}
	response := `{"id":"synthetic-ollama-response","object":"chat.completion","model":"` + r.responseModel + `","choices":[{"index":0,"message":{"role":"assistant","content":"{\"schema_version\":1,\"candidates\":[]}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1200,"completion_tokens":300,"total_tokens":1500}}`
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(response)), Request: request}, nil
}

func ollamaCloudRuntimePolicy(t *testing.T) (runtimeconfig.RuntimePolicy, runtimeconfig.RouteInventory) {
	t.Helper()
	caps, err := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	requiredCheck(t, err)
	price, err := provider.NewRoutePricing(150000, 500000)
	requiredCheck(t, err)
	definitions := make([]runtimeconfig.RouteDefinition, 0, 2)
	for index, id := range []string{"ollama-generation", "ollama-independent-verifier"} {
		providerID, connection, model := "ollama-cloud", "primary/ollama-cloud", "gemma4:31b"
		evidence := []byte(`{"fixture":"synthetic opaque direct-cloud approval, not provider/account truth","source_url":"https://ollama.com/privacy","source_context":"March 2026 transient fulfillment and no-training policy; not numeric retention SLA","synthetic_account_review":"no live entitlement or account-spend guarantee"}`)
		if index == 1 {
			providerID, connection, model = "independent-direct", "primary/independent-direct", "verifier"
			evidence = []byte(`{"fixture":"synthetic distinct direct verifier evidence, not live independence qualification"}`)
		}
		route, err := provider.NewRouteReference(provider.ProviderZonePrivateRemote, providerID, id, connection, model, "")
		requiredCheck(t, err)
		definitions = append(definitions, runtimeconfig.RouteDefinition{Route: route, Capabilities: caps, ContentLogging: provider.ContentLoggingDisabled, Pricing: price, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: provider.RouteRegistryApproved, EvidenceManifest: evidence, OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11})
	}
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), definitions)
	requiredCheck(t, err)
	var generation, verifier string
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		if record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "ollama-generation" {
			generation = record.Identity()
		} else {
			verifier = record.Identity()
		}
	}
	wire := map[string]any{
		"schema_version": 2, "inventory_identity": inventory.Identity(), "review_policy_identity": requiredDigest("synthetic-ollama-review-policy"),
		"min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{"private_remote"}, "content_logging_allowed": false,
		"estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": 1000000, "pinned_route_record_identity": generation, "preferred_route_record_identities": []string{}, "verification_route_record_identity": verifier, "verification_independence": "distinct_provider",
		"publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true,
		"connections": []any{
			map[string]any{"implementation": "openai_chat_completions", "adapter_id": "ollama-generation", "endpoint": "https://ollama.com/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD", "credential_mode": "bearer"},
			map[string]any{"implementation": "openai_responses", "adapter_id": "ollama-independent-verifier", "endpoint": "https://independent.example/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_OLLAMA_VERIFIER", "credential_mode": "bearer"},
		},
	}
	encoded, err := json.Marshal(wire)
	requiredCheck(t, err)
	configuration, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory)
	requiredCheck(t, err)
	requiredCheck(t, configuration.ValidateAgainstInventory(inventory))
	for _, connection := range configuration.Connections() {
		if connection.RequestProfile() != "" || connection.CredentialMode() != "bearer" {
			t.Fatal("generic v2 fixture acquired a profile or non-bearer mode")
		}
	}
	return configuration, inventory
}

func TestCommonRuntimePolicyCatalogOllamaCloudUsesGenericChatGenerationHandler(t *testing.T) {
	for _, test := range []struct {
		name          string
		responseModel string
		withoutProof  bool
	}{
		{name: "gemma4:31b", responseModel: "gemma4:31b"},
		{name: "gemma4:cloud", responseModel: "gemma4:cloud"},
		{name: "missing-handler-proof", responseModel: "gemma4:31b", withoutProof: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			responseModel := test.responseModel
			ctx := context.Background()
			clock := &requiredClock{at: time.Date(2026, 10, 30, 12, 0, 1, 0, time.UTC)}
			configuration, inventory := ollamaCloudRuntimePolicy(t)
			key, err := openai.NewAPIKey([]byte("synthetic-ollama-key"))
			requiredCheck(t, err)
			credentials := &brokeredCountingCredentials{key: key}
			ledger := audit.NewMemoryLedger()
			transport := &ollamaCloudTransport{t: t, ledger: ledger, responseModel: responseModel}
			claimedCredentials := &ollamaCloudCredentials{t: t, delegate: credentials, ledger: ledger}
			catalog, err := runtimecatalog.NewOpenAIRouteDispatcherCatalogWithOptions(inventory, configuration, ollamaCloudResolver{claimedCredentials}, runtimecatalog.OpenAICatalogOptions{HTTPClient: &http.Client{Transport: transport, Timeout: 2 * time.Minute}, HTTPClientIdentity: requiredDigest("synthetic-ollama-cloud-http")})
			requiredCheck(t, err)
			if credentials.calls != 0 || transport.calls != 0 {
				t.Fatal("catalog construction performed inference/key retrieval")
			}
			store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
			requiredCheck(t, err)
			sanitizer := testsupport.NewCleanGenerationSanitizer()
			handler, err := modelhandler.NewGenerationHandler(store, catalog, ledger, clock, sanitizer.ExpectedBinaryDigests())
			requiredCheck(t, err)
			scope, err := audit.NewReviewScope("tenant-a", "repo-a", "ollama-cloud-single-attempt")
			requiredCheck(t, err)
			request := brokeredGenerationRequest(t, scope, clock, configuration, inventory, store, ledger, handler)
			dependency, ok := request.DependencyOutput("context")
			if !ok || !dependency.Available() {
				t.Fatal("generation input dependency missing")
			}
			inputArtifact, err := store.Get(ctx, scope, dependency.OutputIdentity(), clock.Now())
			requiredCheck(t, err)
			input, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
			requiredCheck(t, err)
			authorization := input.Authorization()
			if authorization.Validate() != nil || authorization.ReservedCostMicroUSD() == 0 {
				t.Fatal("nonzero reservation absent")
			}
			sanitizedArtifact, err := store.Get(ctx, scope, input.SanitizedRequestArtifactIdentity(), clock.Now())
			requiredCheck(t, err)
			sanitized, err := review.ParseSanitizedModelRequest(sanitizedArtifact.Payload())
			requiredCheck(t, err)
			neutral, err := sanitized.ProviderRequest()
			requiredCheck(t, err)
			if neutral.Identity() != authorization.RequestIdentity() {
				t.Fatal("authorized sanitized request crossed")
			}
			if test.withoutProof {
				before, err := ledger.Read(ctx, scope, 0, 20)
				requiredCheck(t, err)
				if len(before) != 1 || before[0].Kind() != audit.EventRouteSelected {
					t.Fatal("raw-dispatch fixture did not stop before claim")
				}
				result, err := gateway.DispatchAuthorizedRouteFromCatalog(ctx, catalog, authorization, neutral)
				requiredCheck(t, err)
				if result.Validate() != nil || result.AuthorizationIdentity() != authorization.Identity() || result.Status() != gateway.RouteDispatchFailed || result.Failure() != gateway.RouteFailurePolicyDenied || result.ReplaySafety() != gateway.RouteReplayNotDispatched || result.Response().Identity() != "" || credentials.calls != 0 || transport.calls != 0 {
					t.Fatal("public raw gateway dispatched remote content without handler proof")
				}
				after, err := ledger.Read(ctx, scope, 0, 20)
				requiredCheck(t, err)
				if len(after) != len(before) || after[0].Identity() != before[0].Identity() {
					t.Fatal("raw proof refusal produced a claim or dispatch audit effect")
				}
				return
			}
			transport.payload, err = review.SanitizedCandidatePayload(neutral, scope.Identity())
			requiredCheck(t, err)
			transport.instructions, err = review.TrustedModelRequestInstructions(transport.payload)
			requiredCheck(t, err)
			transport.scope, transport.authorization = scope, authorization
			claimedCredentials.scope, claimedCredentials.authorization = scope, authorization
			completion := handler.Execute(ctx, request)
			if completion.Validate() != nil || credentials.calls != 1 || transport.calls != 1 {
				t.Fatal("Ollama attempt invalid or hidden retry/fallback")
			}
			events, err := ledger.Read(ctx, scope, 0, 20)
			requiredCheck(t, err)
			if len(events) != 4 {
				t.Fatal("actual Ollama attempt audit count changed")
			}
			for index, kind := range []audit.EventKind{audit.EventRouteSelected, audit.EventRouteAttemptClaimed, audit.EventRouteDispatchCompleted, audit.EventRouteCostReconciled} {
				if events[index].Validate() != nil || events[index].Kind() != kind {
					t.Fatal("actual Ollama audit lineage missing")
				}
			}
			if events[1].SubjectIdentity() != authorization.Identity() {
				t.Fatal("Ollama claim not linked to authorization")
			}
			if responseModel != "gemma4:31b" {
				if completion.Status() != controlplane.TaskCompletionFailed || completion.OutputIdentity() != "" {
					t.Fatal("CLI alias response admitted instead of exact direct selector")
				}
				if events[2].SubjectIdentity() == "" || events[3].SubjectIdentity() == "" {
					t.Fatal("failed alias lost outcome/reconciliation audit")
				}
				return
			}
			if completion.Status() != controlplane.TaskCompletionSucceeded {
				t.Fatalf("generic Ollama generation failed: %#v", completion)
			}
			output, err := store.Get(ctx, scope, completion.OutputIdentity(), clock.Now())
			requiredCheck(t, err)
			contextArtifact, err := store.Get(ctx, scope, input.ContextArtifactIdentity(), clock.Now())
			requiredCheck(t, err)
			result, err := modelhandler.ParseGenerationResultArtifact(output, inputArtifact, contextArtifact)
			requiredCheck(t, err)
			usage, err := provider.NewRouteTokenUsage(1200, 300, 0)
			requiredCheck(t, err)
			part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(ollamaCloudCandidateContent))
			requiredCheck(t, err)
			expectedResponse, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
			requiredCheck(t, err)
			execution := result.RouteExecution()
			outcome, reconciliation := execution.Outcome(), execution.Reconciliation()
			if result.Validate() != nil || len(result.Candidates().Findings()) != 0 || execution.Validate() != nil || execution.Authorization().Identity() != authorization.Identity() || outcome.AuthorizationIdentity() != authorization.Identity() || outcome.ResponseIdentity() != expectedResponse.Identity() || result.Candidates().ResponseIdentity() != expectedResponse.Identity() {
				t.Fatal("actual Ollama candidate/execution response lineage changed")
			}
			observed := outcome.Usage()
			if !observed.IsKnown() || observed.InputTokens() != 1200 || observed.OutputTokens() != 300 || observed.CachedInputTokens() != 0 {
				t.Fatal("generic known usage changed")
			}
			const expectedActualCostMicroUSD uint64 = 330
			if reconciliation.Validate() != nil || reconciliation.Status() != gateway.RouteCostWithinReservation || !reconciliation.ActualCost().IsKnown() || reconciliation.ActualCost().TotalCostMicroUSD() != expectedActualCostMicroUSD || reconciliation.ReservedCostMicroUSD() != authorization.ReservedCostMicroUSD() || reconciliation.AttemptAuthorizationIdentity() != authorization.Identity() || reconciliation.AttemptOutcomeIdentity() != outcome.Identity() || reconciliation.RemainingAfterReservationMicroUSD() != authorization.RemainingCostAfterMicroUSD() || reconciliation.RemainingCostMicroUSD() != authorization.RemainingCostBeforeMicroUSD()-expectedActualCostMicroUSD {
				t.Fatal("actual fixed-price reservation/reconciliation changed")
			}
			if events[2].SubjectIdentity() != outcome.Identity() || events[3].SubjectIdentity() != reconciliation.Identity() {
				t.Fatal("Ollama audit subjects not linked to stored execution")
			}
		})
	}
}
