package runtimeconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func openRouterPolicyDocument(t *testing.T) (RouteInventory, []byte) {
	t.Helper()
	generation := routeDefinition(t, "vendor/model")
	var err error
	generation.Route, err = provider.NewRouteReference(provider.ProviderZoneBrokeredRemote, "openrouter", "adapter-a", "primary/openrouter", "vendor/model", "")
	if err != nil {
		t.Fatal(err)
	}
	witness := newBrokeredPrivacyFixture(brokeredPrivacyRouteFixture{"brokered_remote", "openrouter", "adapter-a", "primary/openrouter", "vendor/model", "", ""}, "OPEN_TRESTLE_PROVIDER_OPENROUTER", "tenant-a", "repository-a", "fixture-upstream/region", "2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z")
	manifest, accountIdentity := brokeredPrivacyManifest(t, witness)
	generation.EvidenceManifest = manifest
	verifier := routeDefinition(t, "verifier")
	verifier.Route, err = provider.NewRouteReference(provider.ProviderZonePrivateRemote, "direct", "verifier", "primary/direct", "verifier", "")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := NewRouteInventory(context.Background(), []RouteDefinition{generation, verifier})
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if json.Unmarshal(runtimePolicyDocument(t, inventory), &wire) != nil {
		t.Fatal("fixture policy")
	}
	var generationRecord, verifierRecord, evidenceDigest string
	for _, observed := range inventory.Candidates() {
		record := observed.ResolvedRecord().RouteRegistryRecord()
		if record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "adapter-a" {
			generationRecord, evidenceDigest = record.Identity(), record.EvidenceManifestDigest()
		} else {
			verifierRecord = record.Identity()
		}
	}
	wire["schema_version"] = 3
	wire["allowed_zones"] = []string{"brokered_remote", "private_remote"}
	wire["pinned_route_record_identity"] = generationRecord
	wire["preferred_route_record_identities"] = []string{}
	wire["verification_route_record_identity"] = verifierRecord
	wire["connections"] = []any{
		map[string]any{"implementation": "openai_chat_completions", "adapter_id": "adapter-a", "endpoint": "https://openrouter.ai/api/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_OPENROUTER", "request_profile": "openrouter_zdr_chat_v1", "brokered_route_authority": map[string]any{
			"route_record_identity": generationRecord, "evidence_manifest_digest": evidenceDigest, "account_policy_identity": accountIdentity, "tenant_id": "tenant-a", "repository_id": "repository-a", "provider_slug": "fixture-upstream/region", "valid_from": "2026-10-01T00:00:00Z", "valid_until": "2026-11-01T00:00:00Z",
		}},
		map[string]any{"implementation": "openai_responses", "adapter_id": "verifier", "endpoint": "https://direct.example/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_DIRECT"},
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return inventory, encoded
}

func TestRuntimePolicyV3BindsExplicitBrokeredAuthority(t *testing.T) {
	inventory, encoded := openRouterPolicyDocument(t)
	policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory)
	if err != nil || policy.ValidateAgainstInventory(inventory) != nil {
		t.Fatalf("explicit brokered authority refused: %v", err)
	}
	var wire map[string]any
	json.Unmarshal(encoded, &wire)
	connections := wire["connections"].([]any)
	authority := connections[0].(map[string]any)["brokered_route_authority"].(map[string]any)
	for _, field := range []string{"account_policy_identity", "tenant_id", "repository_id", "provider_slug", "valid_from", "valid_until"} {
		original := authority[field]
		if field == "valid_from" {
			authority[field] = "2026-10-02T00:00:00Z"
		} else if field == "valid_until" {
			authority[field] = "2026-11-02T00:00:00Z"
		} else if field == "account_policy_identity" {
			authority[field] = strings.Repeat("f", 64)
		} else {
			authority[field] = "another-value"
		}
		changed, _ := json.Marshal(wire)
		rebound, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(changed), inventory)
		if err == nil || rebound.Identity() != "" {
			t.Fatalf("policy-only authority %s mutation accepted", field)
		}
		authority[field] = original
	}
}

func TestRuntimePolicyV3RejectsUnboundBrokeredAuthority(t *testing.T) {
	inventory, encoded := openRouterPolicyDocument(t)
	for _, name := range []string{"profile missing", "profile unknown", "authority missing", "authority null", "wrong record", "wrong evidence", "zero account", "empty tenant", "empty repository", "bad slug", "reversed validity", "wrong endpoint", "wrong protocol", "no credential", "historical v2", "case alias"} {
		t.Run(name, func(t *testing.T) {
			var wire map[string]any
			json.Unmarshal(encoded, &wire)
			connection := wire["connections"].([]any)[0].(map[string]any)
			authority := connection["brokered_route_authority"].(map[string]any)
			switch name {
			case "profile missing":
				delete(connection, "request_profile")
			case "profile unknown":
				connection["request_profile"] = "custom"
			case "authority missing":
				delete(connection, "brokered_route_authority")
			case "authority null":
				connection["brokered_route_authority"] = nil
			case "wrong record":
				authority["route_record_identity"] = strings.Repeat("b", 64)
			case "wrong evidence":
				authority["evidence_manifest_digest"] = strings.Repeat("b", 64)
			case "zero account":
				authority["account_policy_identity"] = strings.Repeat("0", 64)
			case "empty tenant":
				authority["tenant_id"] = ""
			case "empty repository":
				authority["repository_id"] = ""
			case "bad slug":
				authority["provider_slug"] = "../provider"
			case "reversed validity":
				authority["valid_until"] = authority["valid_from"]
			case "wrong endpoint":
				connection["endpoint"] = "https://another.example/v1"
			case "wrong protocol":
				connection["implementation"] = "openai_responses"
			case "no credential":
				connection["credential_mode"] = "none"
				delete(connection, "credential_environment")
			case "historical v2":
				wire["schema_version"] = 2
			case "case alias":
				connection["Request_profile"] = connection["request_profile"]
				delete(connection, "request_profile")
			}
			changed, _ := json.Marshal(wire)
			if policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(changed), inventory); err == nil || policy.Identity() != "" {
				t.Fatal("unbound brokered authority accepted")
			}
		})
	}
}

func TestRuntimePolicyHistoricalVersionsRefuseProfilePresence(t *testing.T) {
	inventory, err := NewRouteInventory(context.Background(), []RouteDefinition{routeDefinition(t, "model-a")})
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{1, 2} {
		for _, key := range []string{"request_profile", "Request_profile", "brokered_route_authority", "Brokered_route_authority"} {
			for _, value := range []any{nil, "", map[string]any{}} {
				var document map[string]any
				json.Unmarshal(runtimePolicyDocument(t, inventory), &document)
				document["schema_version"] = version
				if version == 2 {
					document["verification_route_record_identity"] = inventory.Candidates()[0].ResolvedRecord().RouteRegistryRecord().Identity()
				}
				document["connections"].([]any)[0].(map[string]any)[key] = value
				encoded, _ := json.Marshal(document)
				if result, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory); err == nil || result.Identity() != "" {
					t.Fatalf("historical v%d admitted %s presence", version, key)
				}
			}
		}
	}
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
