package runtimeconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

type privacyWitnessSourceFixture struct {
	URL           string `json:"url"`
	RetrievedAt   string `json:"retrieved_at"`
	ContentSHA256 string `json:"content_sha256"`
}

type privacyWitnessRouteFixture struct {
	Zone              string `json:"zone"`
	ProviderID        string `json:"provider_id"`
	AdapterID         string `json:"adapter_id"`
	ConnectionID      string `json:"connection_id"`
	ModelID           string `json:"model_id"`
	ModelVersion      string `json:"model_version"`
	EffectiveSelector string `json:"effective_selector"`
}

type privacyWitnessAccountFixture struct {
	AuthorityLabel                 string                      `json:"authority_label"`
	CredentialReferenceIdentity    string                      `json:"credential_reference_identity"`
	ContentLogging                 string                      `json:"content_logging"`
	Training                       string                      `json:"training"`
	SafetyRetentionScope           string                      `json:"safety_retention_scope"`
	EffectiveSafetyRetentionGoogle string                      `json:"effective_safety_retention_google"`
	EffectiveSafetyRetentionOther  string                      `json:"effective_safety_retention_other"`
	ReviewEvidence                 privacyWitnessSourceFixture `json:"review_evidence"`
}

type privacyWitnessFixture struct {
	Contract          string                     `json:"contract"`
	SchemaVersion     int                        `json:"schema_version"`
	Route             privacyWitnessRouteFixture `json:"route"`
	Endpoint          string                     `json:"endpoint"`
	RequestProfile    string                     `json:"request_profile"`
	Protocol          string                     `json:"protocol"`
	CredentialMode    string                     `json:"credential_mode"`
	ProviderSlug      string                     `json:"provider_slug"`
	ProviderSlugScope string                     `json:"provider_slug_scope"`
	Upstream          struct {
		RetentionContract string                      `json:"retention_contract"`
		Training          string                      `json:"training"`
		Evidence          privacyWitnessSourceFixture `json:"evidence"`
	} `json:"upstream"`
	Broker struct {
		RetentionContract string                      `json:"retention_contract"`
		Evidence          privacyWitnessSourceFixture `json:"evidence"`
	} `json:"broker"`
	SlugEvidence              privacyWitnessSourceFixture  `json:"slug_evidence"`
	Account                   privacyWitnessAccountFixture `json:"account"`
	TenantID                  string                       `json:"tenant_id"`
	RepositoryID              string                       `json:"repository_id"`
	AcceptedRetentionContract string                       `json:"accepted_retention_contract"`
	ReviewedAt                string                       `json:"reviewed_at"`
	ValidFrom                 string                       `json:"valid_from"`
	ValidUntil                string                       `json:"valid_until"`
	BYOK                      string                       `json:"byok"`
	PrivateEndpoints          string                       `json:"private_endpoints"`
	Tools                     string                       `json:"tools"`
	Plugins                   string                       `json:"plugins"`
}

func privacyFixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func privacyFixtureDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func privacyFixtureAccountIdentity(t *testing.T, account privacyWitnessAccountFixture) string {
	t.Helper()
	return privacyFixtureDigest(privacyFixtureJSON(t, struct {
		Contract string                       `json:"contract"`
		Version  int                          `json:"version"`
		Account  privacyWitnessAccountFixture `json:"account"`
	}{"open-trestle/openrouter-account-policy", 2, account}))
}

func privacyFixtureWitness(t *testing.T) privacyWitnessFixture {
	t.Helper()
	var witness privacyWitnessFixture
	witness.Contract, witness.SchemaVersion = "open-trestle/openrouter-privacy-witness", 2
	witness.Route = privacyWitnessRouteFixture{"brokered_remote", "openrouter", "adapter-a", "primary/openrouter", "vendor/model", "fixture-version", "fixture-version"}
	witness.Endpoint, witness.RequestProfile = "https://openrouter.ai/api/v1", "openrouter_zdr_chat_v1"
	witness.Protocol, witness.CredentialMode = "openai_chat_completions", "bearer"
	witness.ProviderSlug, witness.ProviderSlugScope = "fixture-upstream/region", "all_slug_matches"
	witness.Upstream.RetentionContract, witness.Upstream.Training = "openrouter_zdr_with_documented_exceptions", "disabled"
	witness.Broker.RetentionContract = witness.Upstream.RetentionContract
	witness.AcceptedRetentionContract = witness.Upstream.RetentionContract
	witness.Upstream.Evidence = privacyWitnessSourceFixture{"https://evidence.fixture.invalid/upstream-model-slug-scope", "2026-09-30T00:00:00Z", privacyFixtureDigest([]byte("synthetic upstream model/slug review, not provider evidence"))}
	witness.Broker.Evidence = privacyWitnessSourceFixture{"https://evidence.fixture.invalid/broker-retention-exceptions", "2026-09-30T00:00:00Z", privacyFixtureDigest([]byte("synthetic broker exceptions review, not provider evidence"))}
	witness.SlugEvidence = privacyWitnessSourceFixture{"https://evidence.fixture.invalid/all-zdr-eligible-slug-matches", "2026-09-30T00:00:00Z", privacyFixtureDigest([]byte("synthetic slug coverage review, not provider evidence"))}
	witness.Account = privacyWitnessAccountFixture{
		AuthorityLabel:              "synthetic account review, not live approval",
		CredentialReferenceIdentity: privacyFixtureDigest([]byte("open-trestle/provider-credential-environment/OPEN_TRESTLE_PROVIDER_OPENROUTER")),
		ContentLogging:              "disabled", Training: "disabled",
		SafetyRetentionScope:           "effective_account_and_guardrails",
		EffectiveSafetyRetentionGoogle: "denied",
		EffectiveSafetyRetentionOther:  "denied",
		ReviewEvidence:                 privacyWitnessSourceFixture{"https://account-review.fixture.invalid/reviews/synthetic-account", "2026-09-30T00:00:00Z", privacyFixtureDigest([]byte("synthetic account review, not public privacy policy or live approval"))},
	}
	witness.TenantID, witness.RepositoryID = "tenant-a", "repository-a"
	witness.ReviewedAt, witness.ValidFrom, witness.ValidUntil = "2026-09-30T00:00:00Z", "2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z"
	witness.BYOK, witness.PrivateEndpoints, witness.Tools, witness.Plugins = "excluded", "excluded", "excluded", "excluded"
	return witness
}

func privacyFixtureManifest(t *testing.T, witness privacyWitnessFixture) []byte {
	t.Helper()
	return privacyFixtureJSON(t, struct {
		OpenRouterPrivacy privacyWitnessFixture `json:"openrouter_privacy"`
	}{witness})
}

func privacyFixtureInventory(t *testing.T, manifest []byte, decoded, brokered bool) RouteInventory {
	t.Helper()
	generation := routeDefinition(t, "vendor/model")
	zone, providerID, connectionID := provider.ProviderZoneBrokeredRemote, "openrouter", "primary/openrouter"
	if !brokered {
		zone, providerID, connectionID = provider.ProviderZonePrivateRemote, "provider-a", "connection-a"
	}
	var err error
	generation.Route, err = provider.NewRouteReference(zone, providerID, "adapter-a", connectionID, "vendor/model", "fixture-version")
	if err != nil {
		t.Fatal(err)
	}
	generation.EvidenceManifest = append([]byte(nil), manifest...)
	verifier := routeDefinition(t, "verifier")
	verifier.Route, err = provider.NewRouteReference(provider.ProviderZonePrivateRemote, "direct", "verifier", "primary/direct", "verifier", "2026-01")
	if err != nil {
		t.Fatal(err)
	}
	definitions := []RouteDefinition{verifier, generation}
	var inventory RouteInventory
	if decoded {
		var base map[string]any
		if err := json.Unmarshal(encodedInventory(t), &base); err != nil {
			t.Fatal(err)
		}
		template := base["routes"].([]any)[0].(map[string]any)
		routes := make([]any, 0, len(definitions))
		for _, definition := range definitions {
			item := make(map[string]any, len(template))
			for key, value := range template {
				item[key] = value
			}
			route := definition.Route
			item["zone"], item["provider_id"], item["adapter_id"] = route.Zone().String(), route.ProviderID(), route.AdapterID()
			item["connection_id"], item["model_id"], item["model_version"] = route.ConnectionID(), route.ModelID(), route.ModelVersion()
			features := make([]string, 0, len(definition.Capabilities.SupportedFeatures()))
			for _, feature := range definition.Capabilities.SupportedFeatures() {
				features = append(features, feature.String())
			}
			item["max_context_tokens"], item["max_output_tokens"], item["features"] = definition.Capabilities.MaxContextTokens(), definition.Capabilities.MaxOutputTokens(), features
			item["content_logging"], item["pricing_known"] = definition.ContentLogging.String(), definition.Pricing.IsKnown()
			item["input_micro_usd_per_million_tokens"], item["output_micro_usd_per_million_tokens"] = definition.Pricing.InputMicroUSDPerMillionTokens(), definition.Pricing.OutputMicroUSDPerMillionTokens()
			item["quality"], item["registry_revision"], item["registry_status"] = definition.Quality.String(), definition.RegistryRevision, definition.RegistryStatus.String()
			item["operational_revision"], item["health"], item["quota"] = definition.OperationalRevision, definition.Health.String(), definition.Quota.String()
			item["performance_revision"], item["latency_known"] = definition.PerformanceRevision, definition.P95LatencyMilliseconds != 0
			item["p95_latency_milliseconds"], item["latency_sample_count"] = definition.P95LatencyMilliseconds, definition.LatencySampleCount
			item["evidence_manifest_base64"] = base64.StdEncoding.EncodeToString(definition.EvidenceManifest)
			routes = append(routes, item)
		}
		base["routes"] = routes
		inventory, err = DecodeRouteInventory(context.Background(), bytes.NewReader(privacyFixtureJSON(t, base)))
	} else {
		inventory, err = NewRouteInventory(context.Background(), definitions)
	}
	if err != nil || inventory.Validate() != nil {
		t.Fatalf("generic inventory construction refused: %v", err)
	}
	return inventory
}

func privacyFixturePolicy(t *testing.T, inventory RouteInventory, account string, brokered bool, version int) map[string]any {
	t.Helper()
	var wire map[string]any
	if err := json.Unmarshal(runtimePolicyDocument(t, inventory), &wire); err != nil {
		t.Fatal(err)
	}
	var generationRecord, verifierRecord, evidenceDigest string
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		if record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "adapter-a" {
			generationRecord, evidenceDigest = record.Identity(), record.EvidenceManifestDigest()
		} else {
			verifierRecord = record.Identity()
		}
	}
	wire["schema_version"] = version
	wire["pinned_route_record_identity"], wire["preferred_route_record_identities"] = generationRecord, []string{}
	if version >= 2 {
		wire["verification_route_record_identity"] = verifierRecord
	}
	generation := map[string]any{"implementation": "openai_responses", "adapter_id": "adapter-a", "endpoint": "https://direct.example/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_OPENROUTER"}
	if brokered {
		generation["implementation"] = "openai_chat_completions"
		wire["allowed_zones"] = []string{"brokered_remote", "private_remote"}
		generation["endpoint"], generation["request_profile"] = "https://openrouter.ai/api/v1", "openrouter_zdr_chat_v1"
		generation["brokered_route_authority"] = map[string]any{
			"route_record_identity": generationRecord, "evidence_manifest_digest": evidenceDigest, "account_policy_identity": account,
			"tenant_id": "tenant-a", "repository_id": "repository-a", "provider_slug": "fixture-upstream/region", "valid_from": "2026-10-01T00:00:00Z", "valid_until": "2026-11-01T00:00:00Z",
		}
	}
	wire["connections"] = []any{generation, map[string]any{"implementation": "openai_responses", "adapter_id": "verifier", "endpoint": "https://verifier.example/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_DIRECT"}}
	return wire
}
