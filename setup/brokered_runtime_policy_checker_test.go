package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func setupBrokeredDocuments(t *testing.T, mutate func(map[string]any)) ([]byte, []byte) {
	t.Helper()
	return setupBrokeredDocumentsWithWitness(t, nil, mutate)
}

func setupBrokeredDocumentsWithWitness(t *testing.T, mutateWitness func(*brokeredPrivacyFixture), mutate func(map[string]any)) ([]byte, []byte) {
	t.Helper()
	invDoc, polDoc := setupRuntimeDocuments(t, "private_remote", []string{"https://openrouter.ai/api/v1", "https://verifier.example/v1"}, 100000, false)
	var inventoryWire, policyWire map[string]any
	if json.Unmarshal(invDoc, &inventoryWire) != nil || json.Unmarshal(polDoc, &policyWire) != nil {
		t.Fatal("decode fixture")
	}
	routes := inventoryWire["routes"].([]any)
	broker := routes[0].(map[string]any)
	broker["zone"], broker["provider_id"] = "brokered_remote", "openrouter"
	connection := policyWire["connections"].([]any)[0].(map[string]any)
	witness := newBrokeredPrivacyFixture(brokeredPrivacyRouteFixture{"brokered_remote", "openrouter", broker["adapter_id"].(string), broker["connection_id"].(string), broker["model_id"].(string), broker["model_version"].(string), ""}, connection["credential_environment"].(string), "tenant-a", "repo-a", "reviewed-provider", "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z")
	if mutateWitness != nil {
		mutateWitness(&witness)
	}
	manifest, accountIdentity := brokeredPrivacyManifest(t, witness)
	broker["evidence_manifest_base64"] = base64.StdEncoding.EncodeToString(manifest)
	invDoc, _ = json.Marshal(inventoryWire)
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(invDoc))
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]string{}
	evidence := ""
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		adapter := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()
		records[adapter] = record.Identity()
		if adapter == "adapter-a" {
			evidence = record.EvidenceManifestDigest()
		}
	}
	policyWire["schema_version"] = 3
	policyWire["inventory_identity"] = inventory.Identity()
	policyWire["allowed_zones"] = []string{"brokered_remote", "private_remote"}
	policyWire["pinned_route_record_identity"] = records["adapter-a"]
	policyWire["verification_route_record_identity"] = records["adapter-b"]
	connections := policyWire["connections"].([]any)
	connection = connections[0].(map[string]any)
	connection["implementation"] = "openai_chat_completions"
	connection["request_profile"] = runtimeconfig.OpenRouterZDRChatProfile
	connection["brokered_route_authority"] = map[string]any{
		"route_record_identity": records["adapter-a"], "evidence_manifest_digest": evidence,
		"account_policy_identity": accountIdentity, "tenant_id": witness.TenantID, "repository_id": witness.RepositoryID,
		"provider_slug": witness.ProviderSlug, "valid_from": witness.ValidFrom, "valid_until": witness.ValidUntil,
	}
	if mutate != nil {
		mutate(policyWire)
	}
	polDoc, _ = json.Marshal(policyWire)
	return invDoc, polDoc
}

func TestSetupBrokeredExactPairPassesExistingReceiptAndDryRunPath(t *testing.T) {
	invDoc, polDoc := setupBrokeredDocuments(t, nil)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(1))
	checker, err := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	if err != nil {
		t.Fatal(err)
	}
	remote, err := NewRemoteProviderAuthorizationChecker(checker)
	if err != nil {
		t.Fatal(err)
	}
	state, err := OpenStateFile(filepath.Join(t.TempDir(), "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(state, []Checker{checker, remote}, testRunnerClock{time.UnixMilli(2).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []CheckKey{CheckRemoteProviderAuthorized, CheckPolicyValidated} {
		next, receipt, err := runner.Run(context.Background(), key)
		if err != nil || receipt.State() != CheckPassed {
			t.Fatalf("%s receipt=%s err=%v", key, receipt.State(), err)
		}
		encoded, err := EncodeCheckReceipt(receipt)
		if err != nil || bytes.Contains(encoded, []byte("openrouter")) || bytes.Contains(encoded, []byte("OPEN_TRESTLE_PROVIDER")) {
			t.Fatal("noncanonical or identifying receipt")
		}
		plan = next
	}
	dry, err := NewDryRunChecker(checker)
	if err != nil {
		t.Fatal(err)
	}
	if result := dry.Check(context.Background(), plan); result.State() != CheckPassed {
		t.Fatalf("dry-run=%s", result.State())
	}
}

func TestSetupBrokeredScopeValidityAndAuthorityFailClosed(t *testing.T) {
	for _, test := range []struct{ name, field, value string }{
		{"expired", "valid_until", "2001-01-01T00:00:00Z"},
		{"future", "valid_from", "2099-01-01T00:00:00Z"},
		{"tenant", "tenant_id", "other-tenant"},
		{"repository", "repository_id", "other-repository"},
		{"record", "route_record_identity", strings.Repeat("b", 64)},
		{"evidence", "evidence_manifest_digest", strings.Repeat("c", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			invDoc, polDoc := setupBrokeredDocuments(t, func(w map[string]any) {
				w["connections"].([]any)[0].(map[string]any)["brokered_route_authority"].(map[string]any)[test.field] = test.value
			})
			inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(invDoc))
			if err != nil {
				t.Fatal(err)
			}
			policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(polDoc), inventory)
			if err == nil || policy.Identity() != "" {
				t.Fatal("policy-only authority mutation accepted")
			}
		})
	}
}

func TestSetupBrokeredPairRequiresDistinctDirectVerifier(t *testing.T) {
	for _, kind := range []string{"credential", "origin", "generation pin", "independence"} {
		t.Run(kind, func(t *testing.T) {
			invDoc, polDoc := setupBrokeredDocuments(t, func(w map[string]any) {
				connections := w["connections"].([]any)
				broker, direct := connections[0].(map[string]any), connections[1].(map[string]any)
				switch kind {
				case "credential":
					direct["credential_environment"] = broker["credential_environment"]
				case "origin":
					direct["endpoint"] = "https://openrouter.ai:443/another-base"
				case "generation pin":
					w["pinned_route_record_identity"] = ""
				case "independence":
					w["verification_independence"], w["publication_minimum_independence"] = "distinct_model", "distinct_model"
				}
			})
			inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
			plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(1))
			checker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
			remote, _ := NewRemoteProviderAuthorizationChecker(checker)
			if checker.Check(context.Background(), plan).State() != CheckBlocked || remote.Check(context.Background(), plan).State() != CheckBlocked {
				t.Fatal("non-independent or unpinned pair passed")
			}
		})
	}
}

func TestSetupBrokeredLocalProfileRefusesBeforeFactory(t *testing.T) {
	invDoc, polDoc := setupBrokeredDocuments(t, nil)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileLocalSingleNode, "tenant-a", "repo-a", "owner", setupTime(1))
	checker, _ := NewRuntimePolicyChecker(inventory, policy, setupRuntimeApproval(t, plan, inventory, policy))
	if checker.Check(context.Background(), plan).State() != CheckBlocked {
		t.Fatal("remote policy accepted locally")
	}
	plan = policyCheckedPlan(t, plan, checker)
	factory := &localInferenceFixtureFactory{}
	local, _ := NewLocalInferenceChecker(checker, factory)
	if local.Check(context.Background(), plan).State() != CheckBlocked || factory.calls != 0 || factory.dispatches != 0 {
		t.Fatal("remote policy reached local credentials/probe seam")
	}
}

func TestSetupBrokeredMalformedOrMissingProfileAuthorityRejectsDecode(t *testing.T) {
	for _, field := range []string{"request_profile", "brokered_route_authority"} {
		invDoc, polDoc := setupBrokeredDocuments(t, func(w map[string]any) { delete(w["connections"].([]any)[0].(map[string]any), field) })
		inventory, _ := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(invDoc))
		if _, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(polDoc), inventory); err == nil {
			t.Fatal("missing profile authority accepted")
		}
	}
}

func TestSetupBrokeredRequiresExactApprovedConfiguration(t *testing.T) {
	invDoc, polDoc := setupBrokeredDocuments(t, nil)
	inventory, policy := parseSetupRuntimeDocuments(t, invDoc, polDoc)
	plan, _ := NewPlan(ProfileControlledHybrid, "tenant-a", "repo-a", "owner", setupTime(1))
	approval := setupRuntimeApproval(t, plan, inventory, policy)
	if _, err := NewRuntimePolicyApproval(plan, inventory.Identity(), policy.Identity(), policy.ReviewPolicyIdentity(), "not-owner"); err == nil {
		t.Fatal("non-owner consent accepted")
	}
	changedInventoryDoc, changedPolicyDoc := setupBrokeredDocumentsWithWitness(t, func(w *brokeredPrivacyFixture) {
		w.Account.AuthorityLabel = "renewed synthetic account review, not live approval"
	}, nil)
	changedInventory, changedPolicy := parseSetupRuntimeDocuments(t, changedInventoryDoc, changedPolicyDoc)
	if changedInventory.Identity() == inventory.Identity() || changedPolicy.Identity() == policy.Identity() {
		t.Fatal("coherent witness renewal did not change configuration identities")
	}
	if _, err := NewRuntimePolicyChecker(changedInventory, changedPolicy, approval); err == nil {
		t.Fatal("old approval accepted changed account authority")
	}
	renewed, err := NewRuntimePolicyChecker(changedInventory, changedPolicy, setupRuntimeApproval(t, plan, changedInventory, changedPolicy))
	if err != nil || renewed.Check(context.Background(), plan).State() != CheckPassed {
		t.Fatalf("new exact approval refused coherent witness renewal: %v", err)
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
	AuthorityLabel              string                       `json:"authority_label"`
	CredentialReferenceIdentity string                       `json:"credential_reference_identity"`
	ContentLogging              string                       `json:"content_logging"`
	Training                    string                       `json:"training"`
	ReviewEvidence              brokeredPrivacySourceFixture `json:"review_evidence"`
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
	}{"open-trestle/openrouter-account-policy", 1, witness.Account})
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
	witness.Contract, witness.SchemaVersion = "open-trestle/openrouter-privacy-witness", 1
	witness.Route = route
	witness.Endpoint, witness.RequestProfile = "https://openrouter.ai/api/v1", "openrouter_zdr_chat_v1"
	witness.Protocol, witness.CredentialMode = "openai_chat_completions", "bearer"
	witness.ProviderSlug, witness.ProviderSlugScope = slug, "all_zdr_eligible_matches"
	witness.Upstream.RetentionContract, witness.Upstream.Training = "openrouter_zdr_with_documented_exceptions", "disabled"
	witness.Broker.RetentionContract, witness.AcceptedRetentionContract = witness.Upstream.RetentionContract, witness.Upstream.RetentionContract
	witness.Upstream.Evidence = brokeredPrivacySourceFixture{"https://evidence.fixture.invalid/upstream-model-slug-scope", from, brokeredPrivacyDigest([]byte("synthetic upstream model/slug review, not provider evidence"))}
	witness.Broker.Evidence = brokeredPrivacySourceFixture{"https://evidence.fixture.invalid/broker-retention-exceptions", from, brokeredPrivacyDigest([]byte("synthetic broker exceptions review, not provider evidence"))}
	witness.SlugEvidence = brokeredPrivacySourceFixture{"https://evidence.fixture.invalid/all-zdr-eligible-slug-matches", from, brokeredPrivacyDigest([]byte("synthetic slug coverage review, not provider evidence"))}
	witness.Account = brokeredPrivacyAccountFixture{
		AuthorityLabel:              "synthetic account review, not live approval",
		CredentialReferenceIdentity: brokeredPrivacyDigest([]byte("open-trestle/provider-credential-environment/" + environment)),
		ContentLogging:              "disabled", Training: "disabled",
		ReviewEvidence: brokeredPrivacySourceFixture{"https://account-review.fixture.invalid/reviews/synthetic-account", from, brokeredPrivacyDigest([]byte("synthetic account review, not public privacy policy or live approval"))},
	}
	witness.TenantID, witness.RepositoryID = tenant, repository
	witness.ReviewedAt, witness.ValidFrom, witness.ValidUntil = from, from, until
	witness.BYOK, witness.PrivateEndpoints, witness.Tools, witness.Plugins = "excluded", "excluded", "excluded", "excluded"
	return witness
}
