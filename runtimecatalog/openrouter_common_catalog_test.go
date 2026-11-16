package runtimecatalog_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/georgejieh/open-trestle/internal/evidence"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type brokeredCountingCredentials struct {
	key   openai.APIKey
	calls int
}

func (p *brokeredCountingCredentials) Retrieve(context.Context) (openai.APIKey, error) {
	p.calls++
	return p.key, nil
}

type brokeredResolver struct{ credentials *brokeredCountingCredentials }

func (r brokeredResolver) ResolveOpenAICredentials(string) (openai.APIKeyProvider, error) {
	return r.credentials, nil
}

type brokeredGenerationTransport struct {
	t      *testing.T
	calls  int
	scopes []string
}

func (r *brokeredGenerationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	r.calls++
	if request.URL.String() != "https://openrouter.ai/api/v1/chat/completions" || request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer synthetic-profile-key" {
		r.t.Fatal("unbound model target/auth")
	}
	var wire struct {
		Model     string
		MaxTokens uint32 `json:"max_tokens"`
		Stream    bool
		Messages  []struct{ Role, Content string }
		Provider  struct {
			ZDR               bool
			Only, Order       []string
			AllowFallbacks    bool `json:"allow_fallbacks"`
			RequireParameters bool `json:"require_parameters"`
		}
	}
	body, err := io.ReadAll(request.Body)
	requiredCheck(r.t, err)
	requiredCheck(r.t, json.Unmarshal(body, &wire))
	if wire.Model != "vendor/model" || wire.MaxTokens == 0 || wire.Stream || !wire.Provider.ZDR || wire.Provider.AllowFallbacks || !wire.Provider.RequireParameters || len(wire.Provider.Only) != 1 || wire.Provider.Only[0] != "fixture-upstream/region" || len(wire.Provider.Order) != 1 || wire.Provider.Order[0] != wire.Provider.Only[0] {
		r.t.Fatalf("unsafe profile wire: %s", body)
	}
	if len(wire.Messages) != 2 || wire.Messages[0].Role != "system" || wire.Messages[1].Role != "user" {
		r.t.Fatal("instruction roles changed")
	}
	instructions, err := review.TrustedModelRequestInstructions([]byte(wire.Messages[1].Content))
	requiredCheck(r.t, err)
	if wire.Messages[0].Content != instructions {
		r.t.Fatal("trusted instruction bytes changed")
	}
	var inner struct {
		Scope string `json:"review_scope_identity"`
		Task  string `json:"task"`
	}
	requiredCheck(r.t, json.Unmarshal([]byte(wire.Messages[1].Content), &inner))
	if inner.Scope == "" || inner.Task != "candidate_generation" {
		r.t.Fatal("not sanitized inner candidate context")
	}
	r.scopes = append(r.scopes, inner.Scope)
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"id":"fixture-chat","object":"chat.completion","model":"vendor/model","choices":[{"index":0,"message":{"role":"assistant","content":"{\"schema_version\":2,\"candidates\":[]}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110}}`)), Request: request}, nil
}

func brokeredRuntimePolicy(t *testing.T, now time.Time) (runtimeconfig.RuntimePolicy, runtimeconfig.RouteInventory) {
	t.Helper()
	inventory, encoded := brokeredRuntimePolicyDocument(t, now, nil)
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory)
	requiredCheck(t, err)
	return policy, inventory
}

func brokeredRuntimePolicyDocument(t *testing.T, now time.Time, mutateManifest func([]byte) []byte) (runtimeconfig.RouteInventory, []byte) {
	t.Helper()
	caps, err := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	requiredCheck(t, err)
	price, err := provider.NewRoutePricing(1, 1)
	requiredCheck(t, err)
	definitions := make([]runtimeconfig.RouteDefinition, 0, 2)
	var accountIdentity string
	for i, id := range []string{"adapter-a", "verifier"} {
		zone, providerID, connection, model := provider.ProviderZoneBrokeredRemote, "openrouter", "primary/openrouter", "vendor/model"
		if i == 1 {
			zone, providerID, connection, model = provider.ProviderZonePrivateRemote, "direct", "primary/direct", "verifier"
		}
		route, err := provider.NewRouteReference(zone, providerID, id, connection, model, "")
		requiredCheck(t, err)
		manifest := []byte(`{"fixture":"direct verifier test evidence"}`)
		if i == 0 {
			witness := newBrokeredPrivacyFixture(brokeredPrivacyRouteFixture{zone.String(), providerID, id, connection, model, "", ""}, "OPEN_TRESTLE_PROVIDER_OPENROUTER", "tenant-a", "repo-a", "fixture-upstream/region", now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Second).Format(time.RFC3339))
			manifest, accountIdentity = brokeredPrivacyManifest(t, witness)
			if mutateManifest != nil {
				manifest = mutateManifest(manifest)
			}
		}
		definitions = append(definitions, runtimeconfig.RouteDefinition{Route: route, Capabilities: caps, ContentLogging: provider.ContentLoggingDisabled, Pricing: price, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: provider.RouteRegistryApproved, EvidenceManifest: manifest, OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11})
	}
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), definitions)
	requiredCheck(t, err)
	var generation, verifier, digest string
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		if record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "adapter-a" {
			generation, digest = record.Identity(), record.EvidenceManifestDigest()
		} else {
			verifier = record.Identity()
		}
	}
	wire := map[string]any{
		"schema_version": 3, "inventory_identity": inventory.Identity(), "review_policy_identity": requiredDigest("brokered-review-policy"),
		"min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{"brokered_remote", "private_remote"}, "content_logging_allowed": false,
		"estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": 1000000, "pinned_route_record_identity": generation, "preferred_route_record_identities": []string{}, "verification_route_record_identity": verifier, "verification_independence": "distinct_provider",
		"publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true,
		"connections": []any{
			map[string]any{"implementation": "openai_chat_completions", "adapter_id": "adapter-a", "endpoint": "https://openrouter.ai/api/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_OPENROUTER", "request_profile": "openrouter_zdr_chat_v1", "brokered_route_authority": map[string]any{"route_record_identity": generation, "evidence_manifest_digest": digest, "account_policy_identity": accountIdentity, "tenant_id": "tenant-a", "repository_id": "repo-a", "provider_slug": "fixture-upstream/region", "valid_from": now.Add(-time.Minute).Format(time.RFC3339), "valid_until": now.Add(time.Second).Format(time.RFC3339)}},
			map[string]any{"implementation": "openai_responses", "adapter_id": "verifier", "endpoint": "https://direct.example/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_DIRECT"},
		},
	}
	encoded, err := json.Marshal(wire)
	requiredCheck(t, err)
	return inventory, encoded
}

func brokeredGenerationRequest(t *testing.T, scope audit.ReviewScope, clock *requiredClock, configuration runtimeconfig.RuntimePolicy, inventory runtimeconfig.RouteInventory, store artifact.Store, ledger audit.Ledger, handler *modelhandler.GenerationHandler) controlplane.TaskExecutionRequest {
	t.Helper()
	ctx := context.Background()
	created := clock.Now().Add(-time.Second)
	memoryScope, err := memorycore.NewScope(scope.TenantID(), scope.RepositoryID(), "actor-a", memorycore.RefVisibilityExact, strings.Repeat("a", 64), []string{"src"})
	requiredCheck(t, err)
	sourceRange, err := evidence.NewSourceRange("src/main.go", 1, 1)
	requiredCheck(t, err)
	snapshot, err := review.NewReviewSnapshot("workspace", requiredDigest("commit"), []evidence.SourceRange{sourceRange})
	requiredCheck(t, err)
	content := []byte("package main\n")
	item, err := evidence.NewEvidenceItem("source-1", evidence.EvidenceKindSource, requiredDigest(string(content)), sourceRange)
	requiredCheck(t, err)
	source, err := review.NewContextSource(review.ContextStageChangedHunk, memorycore.TaintRepositoryControlled, item, content)
	requiredCheck(t, err)
	query, err := memorycore.NewLexicalQuery(memoryScope, "src/main.go", nil, nil, created, 5)
	requiredCheck(t, err)
	retrieval, err := memorycore.NewLexicalIndex().Search(ctx, memoryScope, query)
	requiredCheck(t, err)
	limits, err := review.NewContextLimits(1<<20, 0)
	requiredCheck(t, err)
	packet, err := review.NewContextPacket(scope, memoryScope, snapshot, review.ContextTaskCandidateGeneration, []review.ContextSource{source}, retrieval, limits)
	requiredCheck(t, err)
	raw, err := packet.ProviderRequest()
	requiredCheck(t, err)
	contextArtifact, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{requiredDigest("context-parent")}, raw.Payload(), created, clock.Now().Add(time.Hour))
	requiredCheck(t, err)
	sanitizer := testsupport.NewCleanGenerationSanitizer()
	sanitized, receipt, err := sanitizer.SanitizeGeneration(ctx, raw, scope.Identity())
	requiredCheck(t, err)
	requestArtifact, receiptArtifact, err := review.NewSanitizedEgressArtifacts(contextArtifact, sanitized, receipt, sanitizer.ExpectedBinaryDigests(), created)
	requiredCheck(t, err)
	request, err := sanitized.ProviderRequest()
	requiredCheck(t, err)
	authorizer, err := runtimecatalog.NewGenerationPolicyAuthorizerFromRuntimePolicy(configuration, inventory, ledger)
	requiredCheck(t, err)
	authorization, err := authorizer.Authorize(ctx, scope, request, configuration.ReviewPolicyIdentity(), created)
	requiredCheck(t, err)
	input, err := modelhandler.NewSanitizedGenerationInput(contextArtifact, packet, snapshot, requestArtifact, receiptArtifact, sanitizer.ExpectedBinaryDigests(), authorization)
	requiredCheck(t, err)
	inputArtifact, err := modelhandler.NewGenerationInputArtifact(input, contextArtifact, []string{requiredDigest("task-parent")}, created)
	requiredCheck(t, err)
	for _, value := range []artifact.Artifact{contextArtifact, requestArtifact, receiptArtifact, inputArtifact} {
		_, err = store.Put(ctx, value, clock.Now())
		requiredCheck(t, err)
	}
	return brokeredGenerationTask(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), clock)
}

func TestCommonRuntimePolicyCatalogUsesHandlerProofAcrossRunsAndRejectsExpiryAndRepository(t *testing.T) {
	clock := &requiredClock{at: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	configuration, inventory := brokeredRuntimePolicy(t, clock.Now())
	key, err := openai.NewAPIKey([]byte("synthetic-profile-key"))
	requiredCheck(t, err)
	credentials := &brokeredCountingCredentials{key: key}
	transport := &brokeredGenerationTransport{t: t}
	catalog, err := runtimecatalog.NewOpenAIRouteDispatcherCatalogWithOptions(inventory, configuration, brokeredResolver{credentials}, runtimecatalog.OpenAICatalogOptions{Clock: clock, HTTPClient: &http.Client{Transport: transport, Timeout: 2 * time.Minute}, HTTPClientIdentity: requiredDigest("recording-http")})
	requiredCheck(t, err)
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 100)
	requiredCheck(t, err)
	ledger := audit.NewMemoryLedger()
	sanitizer := testsupport.NewCleanGenerationSanitizer()
	handler, err := modelhandler.NewGenerationHandler(store, catalog, ledger, clock, sanitizer.ExpectedBinaryDigests())
	requiredCheck(t, err)
	for _, run := range []string{"run-a", "run-b"} {
		scope, err := audit.NewReviewScope("tenant-a", "repo-a", run)
		requiredCheck(t, err)
		request := brokeredGenerationRequest(t, scope, clock, configuration, inventory, store, ledger, handler)
		completion := handler.Execute(context.Background(), request)
		if completion.Status() != controlplane.TaskCompletionSucceeded || completion.Validate() != nil {
			t.Fatalf("run=%s completion=%#v", run, completion)
		}
		events, err := ledger.Read(context.Background(), scope, 0, 10)
		requiredCheck(t, err)
		if len(events) != 4 || events[0].Kind() != audit.EventRouteSelected || events[1].Kind() != audit.EventRouteAttemptClaimed || events[2].Kind() != audit.EventRouteDispatchCompleted {
			t.Fatal("real authorizer/handler audit lineage absent")
		}
	}
	if credentials.calls != 2 || transport.calls != 2 || len(transport.scopes) != 2 || transport.scopes[0] == transport.scopes[1] {
		t.Fatal("shared catalog did not bind two exact distinct run proofs")
	}
	wrong, err := audit.NewReviewScope("tenant-a", "other-repo", "run-c")
	requiredCheck(t, err)
	wrongRequest := brokeredGenerationRequest(t, wrong, clock, configuration, inventory, store, ledger, handler)
	if completion := handler.Execute(context.Background(), wrongRequest); completion.Status() != controlplane.TaskCompletionFailed {
		t.Fatal("cross-repository attested handler request admitted")
	}
	expired, err := audit.NewReviewScope("tenant-a", "repo-a", "run-expired")
	requiredCheck(t, err)
	expiredRequest := brokeredGenerationRequest(t, expired, clock, configuration, inventory, store, ledger, handler)
	clock.at = clock.at.Add(time.Second)
	if completion := handler.Execute(context.Background(), expiredRequest); completion.Status() != controlplane.TaskCompletionFailed {
		t.Fatal("authority expired after catalog construction admitted")
	}
	if credentials.calls != 2 || transport.calls != 2 {
		t.Fatalf("denied authority reached credentials=%d HTTP=%d", credentials.calls, transport.calls)
	}
}

func brokeredGenerationTask(t *testing.T, scope audit.ReviewScope, inputIdentity, handlerIdentity string, clock *requiredClock) controlplane.TaskExecutionRequest {
	t.Helper()
	specs := []struct {
		key  string
		kind controlplane.TaskKind
		deps []string
	}{
		{"source", controlplane.TaskAcquireSource, nil}, {"change", controlplane.TaskBuildChange, []string{"source"}},
		{"analysis", controlplane.TaskInspectDeterministic, []string{"change"}}, {"memory", controlplane.TaskRetrieveContext, []string{"change"}},
		{"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}}, {"candidates", controlplane.TaskGenerateCandidates, []string{"context"}},
	}
	tasks := make([]controlplane.TaskDefinition, 0, len(specs))
	for _, spec := range specs {
		attempts := uint8(1)
		identity := strings.Repeat(string('a'+rune(len(tasks))), 64)
		handler := strings.Repeat(string('f'-rune(len(tasks))), 64)
		if spec.key == "candidates" {
			identity = strings.Repeat("6", 64)
			handler = handlerIdentity
			attempts = 1
		}
		task, err := controlplane.NewTaskDefinition(spec.key, spec.kind, identity, handler, spec.deps, attempts, 1000, 30000, true)
		if err != nil {
			t.Fatal(err)
		}
		tasks = append(tasks, task)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("8", 64), strings.Repeat("9", 64), controlplane.ReviewRunAdvisory, tasks)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	at := clock.Now().UnixMilli() - 30
	_, _ = coordinator.Open(context.Background(), plan, time.UnixMilli(at))
	for _, task := range tasks[:len(tasks)-1] {
		at++
		_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(at))
		at++
		lease, _, err := coordinator.ClaimTask(context.Background(), plan, task.Key(), task.HandlerIdentity(), "worker-a", time.UnixMilli(at))
		if err != nil {
			t.Fatal(err)
		}
		outputIdentity := strings.Repeat("7", 64)
		if task.Key() == "context" {
			outputIdentity = inputIdentity
		}
		completion, _ := controlplane.NewTaskSuccess(outputIdentity)
		at++
		if _, err = coordinator.CompleteTask(context.Background(), plan, lease, completion, time.UnixMilli(at)); err != nil {
			t.Fatal(err)
		}
	}
	at++
	_, _ = coordinator.Advance(context.Background(), plan, time.UnixMilli(at))
	at++
	candidate := tasks[len(tasks)-1]
	lease, _, err := coordinator.ClaimTask(context.Background(), plan, candidate.Key(), candidate.HandlerIdentity(), "worker-a", time.UnixMilli(at))
	if err != nil {
		t.Fatal(err)
	}
	_, state, err := coordinator.Resume(context.Background(), plan.Scope())
	if err != nil {
		t.Fatal(err)
	}
	dependencies, err := controlplane.TaskDependencyOutputsFromState(state, candidate)
	if err != nil {
		t.Fatal(err)
	}
	request, err := controlplane.NewTaskExecutionRequestWithDependencies(plan, candidate, lease, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

type brokeredPrivacySourceFixture struct {
	URL           string `json:"url"`
	RetrievedAt   string `json:"retrieved_at"`
	ContentSHA256 string `json:"content_sha256"`
}

type brokeredPrivacyRouteFixture struct {
	Zone              string `json:"zone"`
	ProviderID        string `json:"provider_id"`
	AdapterID         string `json:"adapter_id"`
	ConnectionID      string `json:"connection_id"`
	ModelID           string `json:"model_id"`
	ModelVersion      string `json:"model_version"`
	EffectiveSelector string `json:"effective_selector"`
}

type brokeredPrivacyAccountFixture struct {
	AuthorityLabel                 string                       `json:"authority_label"`
	CredentialReferenceIdentity    string                       `json:"credential_reference_identity"`
	ContentLogging                 string                       `json:"content_logging"`
	Training                       string                       `json:"training"`
	SafetyRetentionScope           string                       `json:"safety_retention_scope"`
	EffectiveSafetyRetentionGoogle string                       `json:"effective_safety_retention_google"`
	EffectiveSafetyRetentionOther  string                       `json:"effective_safety_retention_other"`
	ReviewEvidence                 brokeredPrivacySourceFixture `json:"review_evidence"`
}

type brokeredPrivacyFixture struct {
	Contract          string                      `json:"contract"`
	SchemaVersion     int                         `json:"schema_version"`
	Route             brokeredPrivacyRouteFixture `json:"route"`
	Endpoint          string                      `json:"endpoint"`
	RequestProfile    string                      `json:"request_profile"`
	Protocol          string                      `json:"protocol"`
	CredentialMode    string                      `json:"credential_mode"`
	ProviderSlug      string                      `json:"provider_slug"`
	ProviderSlugScope string                      `json:"provider_slug_scope"`
	Upstream          struct {
		RetentionContract string                       `json:"retention_contract"`
		Training          string                       `json:"training"`
		Evidence          brokeredPrivacySourceFixture `json:"evidence"`
	} `json:"upstream"`
	Broker struct {
		RetentionContract string                       `json:"retention_contract"`
		Evidence          brokeredPrivacySourceFixture `json:"evidence"`
	} `json:"broker"`
	SlugEvidence              brokeredPrivacySourceFixture  `json:"slug_evidence"`
	Account                   brokeredPrivacyAccountFixture `json:"account"`
	TenantID                  string                        `json:"tenant_id"`
	RepositoryID              string                        `json:"repository_id"`
	AcceptedRetentionContract string                        `json:"accepted_retention_contract"`
	ReviewedAt                string                        `json:"reviewed_at"`
	ValidFrom                 string                        `json:"valid_from"`
	ValidUntil                string                        `json:"valid_until"`
	BYOK                      string                        `json:"byok"`
	PrivateEndpoints          string                        `json:"private_endpoints"`
	Tools                     string                        `json:"tools"`
	Plugins                   string                        `json:"plugins"`
}

func brokeredPrivacyJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func brokeredPrivacyDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func brokeredPrivacyManifest(t *testing.T, witness brokeredPrivacyFixture) ([]byte, string) {
	t.Helper()
	account := brokeredPrivacyJSON(t, struct {
		Contract string                        `json:"contract"`
		Version  int                           `json:"version"`
		Account  brokeredPrivacyAccountFixture `json:"account"`
	}{"open-trestle/openrouter-account-policy", 2, witness.Account})
	manifest := brokeredPrivacyJSON(t, struct {
		OpenRouterPrivacy brokeredPrivacyFixture `json:"openrouter_privacy"`
	}{witness})
	return manifest, brokeredPrivacyDigest(account)
}

// All evidence is synthetic and does not attest to a live provider or account.
func newBrokeredPrivacyFixture(route brokeredPrivacyRouteFixture, environment, tenant, repository, slug, from, until string) brokeredPrivacyFixture {
	if route.ModelVersion != "" {
		route.EffectiveSelector = route.ModelVersion
	} else {
		route.EffectiveSelector = route.ModelID
	}
	var witness brokeredPrivacyFixture
	witness.Contract, witness.SchemaVersion = "open-trestle/openrouter-privacy-witness", 2
	witness.Route = route
	witness.Endpoint, witness.RequestProfile = "https://openrouter.ai/api/v1", "openrouter_zdr_chat_v1"
	witness.Protocol, witness.CredentialMode = "openai_chat_completions", "bearer"
	witness.ProviderSlug, witness.ProviderSlugScope = slug, "all_slug_matches"
	witness.Upstream.RetentionContract, witness.Upstream.Training = "openrouter_zdr_with_documented_exceptions", "disabled"
	witness.Broker.RetentionContract, witness.AcceptedRetentionContract = witness.Upstream.RetentionContract, witness.Upstream.RetentionContract
	witness.Upstream.Evidence = brokeredPrivacySourceFixture{"https://evidence.fixture.invalid/upstream-model-slug-scope", from, brokeredPrivacyDigest([]byte("synthetic upstream model/slug review, not provider evidence"))}
	witness.Broker.Evidence = brokeredPrivacySourceFixture{"https://evidence.fixture.invalid/broker-retention-exceptions", from, brokeredPrivacyDigest([]byte("synthetic broker exceptions review, not provider evidence"))}
	witness.SlugEvidence = brokeredPrivacySourceFixture{"https://evidence.fixture.invalid/all-zdr-eligible-slug-matches", from, brokeredPrivacyDigest([]byte("synthetic slug coverage review, not provider evidence"))}
	witness.Account = brokeredPrivacyAccountFixture{
		AuthorityLabel:              "synthetic account review, not live approval",
		CredentialReferenceIdentity: brokeredPrivacyDigest([]byte("open-trestle/provider-credential-environment/" + environment)),
		ContentLogging:              "disabled", Training: "disabled",
		SafetyRetentionScope:           "effective_account_and_guardrails",
		EffectiveSafetyRetentionGoogle: "denied",
		EffectiveSafetyRetentionOther:  "denied",
		ReviewEvidence:                 brokeredPrivacySourceFixture{"https://account-review.fixture.invalid/reviews/synthetic-account", from, brokeredPrivacyDigest([]byte("synthetic account review, not public privacy policy or live approval"))},
	}
	witness.TenantID, witness.RepositoryID = tenant, repository
	witness.ReviewedAt, witness.ValidFrom, witness.ValidUntil = from, from, until
	witness.BYOK, witness.PrivateEndpoints, witness.Tools, witness.Plugins = "excluded", "excluded", "excluded", "excluded"
	return witness
}
