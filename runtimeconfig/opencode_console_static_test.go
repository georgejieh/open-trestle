package runtimeconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func openCodeConsoleStaticFixture(t *testing.T, mutateManifest func([]byte) []byte) (RouteInventory, map[string]any) {
	t.Helper()
	ctx := context.Background()
	digest := func(value string) string { sum := sha256.Sum256([]byte(value)); return hex.EncodeToString(sum[:]) }
	marshal := func(value any) []byte {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	type source struct {
		URL           string `json:"url"`
		RetrievedAt   string `json:"retrieved_at"`
		ContentSHA256 string `json:"content_sha256"`
	}
	account := struct {
		AuthorityLabel              string `json:"authority_label"`
		CredentialReferenceIdentity string `json:"credential_reference_identity"`
		BillingMode                 string `json:"billing_mode"`
		KeyKind                     string `json:"key_kind"`
		ModelsRequest               bool   `json:"models_request"`
		WorkspaceMembership         string `json:"workspace_membership"`
		PrivacyTraining             string `json:"privacy_training"`
		AutoRecharge                string `json:"auto_recharge"`
		ReviewEvidence              source `json:"review_evidence"`
	}{"synthetic Console single-member account, not live approval", digest("open-trestle/provider-credential-environment/OPEN_TRESTLE_PROVIDER_OPENCODE_CONSOLE"), "prepaid_balance", "personal", true, "single_member", "disabled", "disabled", source{"https://account-review.fixture.invalid/console/prepaid-privacy", "2026-10-29T00:00:00Z", digest("synthetic prepaid account privacy and auto-recharge off review")}}
	accountPreimage := struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Account  any    `json:"account"`
	}{"open-trestle/opencode-console-account-policy", 1, account}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(`{"opencode_console_privacy":{"contract":"open-trestle/opencode-console-privacy-witness","schema_version":1,"route":{"zone":"brokered_remote","provider_id":"opencode-console","adapter_id":"adapter-a","connection_id":"primary/opencode-console","model_id":"glm-5.3-flash","model_version":"","effective_selector":"glm-5.3-flash"},"endpoint":"https://opencode.ai/inference/openai/v1","request_profile":"opencode_console_chat_v1","protocol":"openai_chat_completions","credential_mode":"bearer","model_privacy":{"training":"disabled","retention_days":0},"broker_privacy":{"retention_contract":"model_specific_documented_zero_days"},"tenant_id":"tenant-a","repository_id":"repository-a","reviewed_at":"2026-10-29T00:00:00Z","valid_from":"2026-10-29T00:00:00Z","valid_until":"2026-11-01T00:00:00Z","byok":"excluded","tools":"excluded","plugins":"excluded","streaming":"excluded","client":{"user_agent":"open-trestle/1","session_derivation":"authorized_review_scope_sha256_v1"}}}`), &manifest); err != nil {
		t.Fatal(err)
	}
	witness := manifest["opencode_console_privacy"].(map[string]any)
	witness["account"] = account
	witness["model_privacy"].(map[string]any)["evidence"] = source{"https://evidence.fixture.invalid/console/glm-5.3-flash-privacy", "2026-10-29T00:00:00Z", digest("synthetic documented exact model zero-day no-training review")}
	witness["broker_privacy"].(map[string]any)["evidence"] = source{"https://evidence.fixture.invalid/console/broker-privacy-scope", "2026-10-29T00:00:00Z", digest("synthetic broker privacy scope review")}
	generation := routeDefinition(t, "glm-5.3-flash")
	var err error
	generation.Route, err = provider.NewRouteReference(provider.ProviderZoneBrokeredRemote, "opencode-console", "adapter-a", "primary/opencode-console", "glm-5.3-flash", "")
	if err != nil {
		t.Fatal(err)
	}
	generation.EvidenceManifest = marshal(manifest)
	if mutateManifest != nil {
		generation.EvidenceManifest = mutateManifest(generation.EvidenceManifest)
	}
	verifier := routeDefinition(t, "verifier")
	verifier.Route, err = provider.NewRouteReference(provider.ProviderZonePrivateRemote, "direct", "verifier", "primary/direct", "verifier", "")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := NewRouteInventory(ctx, []RouteDefinition{generation, verifier})
	if err != nil || inventory.Validate() != nil {
		t.Fatalf("fixture inventory invalid: %v", err)
	}
	var recordID, evidenceID, verifierID string
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		if record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "adapter-a" {
			recordID, evidenceID = record.Identity(), record.EvidenceManifestDigest()
		} else {
			verifierID = record.Identity()
		}
	}
	var policyWire map[string]any
	if err := json.Unmarshal(runtimePolicyDocument(t, inventory), &policyWire); err != nil {
		t.Fatal(err)
	}
	policyWire["schema_version"], policyWire["allowed_zones"] = 5, []string{"brokered_remote", "private_remote"}
	policyWire["pinned_route_record_identity"], policyWire["preferred_route_record_identities"], policyWire["verification_route_record_identity"] = recordID, []string{}, verifierID
	policyWire["connections"] = []any{
		map[string]any{"implementation": "openai_chat_completions", "adapter_id": "adapter-a", "endpoint": "https://opencode.ai/inference/openai/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_OPENCODE_CONSOLE", "request_profile": "opencode_console_chat_v1", "opencode_console_authority": map[string]any{"route_record_identity": recordID, "evidence_manifest_digest": evidenceID, "account_policy_identity": digest(string(marshal(accountPreimage))), "tenant_id": "tenant-a", "repository_id": "repository-a", "valid_from": "2026-10-29T00:00:00Z", "valid_until": "2026-11-01T00:00:00Z"}},
		map[string]any{"implementation": "openai_responses", "adapter_id": "verifier", "endpoint": "https://direct.example/v1", "credential_environment": "OPEN_TRESTLE_PROVIDER_DIRECT"},
	}
	return inventory, policyWire
}

func decodeOpenCodeConsoleStatic(t *testing.T, inventory RouteInventory, wire map[string]any) (RuntimePolicy, error) {
	t.Helper()
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory)
}
func TestOpenCodeConsoleStaticWitnessAdmissionAndCurrentWindow(t *testing.T) {
	inventory, wire := openCodeConsoleStaticFixture(t, nil)
	policy, err := decodeOpenCodeConsoleStatic(t, inventory, wire)
	if err != nil || policy.ValidateAgainstInventory(inventory) != nil {
		t.Fatal("valid synthetic Console declaration refused", err)
	}
	var authority OpenCodeConsoleRouteAuthority
	for _, connection := range policy.Connections() {
		if connection.RequestProfile() == OpenCodeConsoleChatProfile {
			authority = connection.OpenCodeConsoleAuthority()
		}
	}
	if authority.RouteRecordIdentity() == "" || authority.AccountPolicyIdentity() == "" || authority.TenantID() != "tenant-a" || authority.RepositoryID() != "repository-a" {
		t.Fatal("Console authority not retained")
	}
	for _, test := range []struct {
		at   time.Time
		want bool
	}{{authority.ValidFrom().Add(-time.Nanosecond), false}, {authority.ValidFrom(), true}, {authority.ValidUntil().Add(-time.Nanosecond), true}, {authority.ValidUntil(), false}} {
		if inventory.OpenCodeConsolePrivacyCurrent(authority.RouteRecordIdentity(), test.at) != test.want || authority.Current(test.at) != test.want {
			t.Fatal("wrong exact declaration window")
		}
	}
	if inventory.OpenCodeConsolePrivacyCurrent(strings.Repeat("e", 64), authority.ValidFrom()) || inventory.OpenRouterPrivacyCurrent(authority.RouteRecordIdentity(), authority.ValidFrom()) {
		t.Fatal("projection crossed record/provider")
	}
}
func TestOpenCodeConsoleStaticRefusesMalformedWitness(t *testing.T) {
	for name, mutation := range map[string]func(string) string{
		"missing":      func(s string) string { return `{"opaque":"legacy evidence"}` },
		"null section": func(s string) string { return `{"opencode_console_privacy":null}` },
		"duplicate": func(s string) string {
			return strings.Replace(s, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)
		},
		"case":                  func(s string) string { return strings.Replace(s, `"model_privacy"`, `"Model_privacy"`, 1) },
		"null retention":        func(s string) string { return strings.Replace(s, `"retention_days":0`, `"retention_days":null`, 1) },
		"missing retention":     func(s string) string { return strings.Replace(s, `"retention_days":0,`, ``, 1) },
		"positive retention":    func(s string) string { return strings.Replace(s, `"retention_days":0`, `"retention_days":1`, 1) },
		"missing model version": func(s string) string { return strings.Replace(s, `"model_version":"",`, ``, 1) },
		"null model version":    func(s string) string { return strings.Replace(s, `"model_version":""`, `"model_version":null`, 1) },
		"wrong model": func(s string) string {
			return strings.Replace(s, `"model_id":"glm-5.3-flash"`, `"model_id":"other-model"`, 1)
		},
		"wrong selector": func(s string) string {
			return strings.Replace(s, `"effective_selector":"glm-5.3-flash"`, `"effective_selector":"other-model"`, 1)
		},
		"auto recharge": func(s string) string {
			return strings.Replace(s, `"auto_recharge":"disabled"`, `"auto_recharge":"enabled"`, 1)
		},
		"training": func(s string) string {
			return strings.Replace(s, `"privacy_training":"disabled"`, `"privacy_training":"enabled"`, 1)
		},
		"membership": func(s string) string {
			return strings.Replace(s, `"workspace_membership":"single_member"`, `"workspace_membership":"team"`, 1)
		},
		"review after from": func(s string) string {
			return strings.Replace(s, `"reviewed_at":"2026-10-29T00:00:00Z"`, `"reviewed_at":"2026-10-30T00:00:00Z"`, 1)
		},
		"unknown client": func(s string) string {
			return strings.Replace(s, `"user_agent":"open-trestle/1"`, `"user_agent":"open-trestle/1","extra":true`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			inventory, wire := openCodeConsoleStaticFixture(t, func(encoded []byte) []byte {
				changed := mutation(string(encoded))
				if changed == string(encoded) {
					t.Fatal("mutation did not reach fixture")
				}
				return []byte(changed)
			})
			policy, err := decodeOpenCodeConsoleStatic(t, inventory, wire)
			if err == nil || policy.Identity() != "" {
				t.Fatal("invalid witness admitted")
			}
		})
	}
}
func TestOpenCodeConsoleStaticRefusesPolicyOnlyChangesAndHistoricalPresence(t *testing.T) {
	for _, field := range []string{"account_policy_identity", "tenant_id", "repository_id", "valid_from", "valid_until", "credential_environment", "both authorities", "extra field", "null authority", "v1", "v2", "v3", "v4"} {
		t.Run(field, func(t *testing.T) {
			inventory, wire := openCodeConsoleStaticFixture(t, nil)
			connection := wire["connections"].([]any)[0].(map[string]any)
			authority := connection["opencode_console_authority"].(map[string]any)
			switch field {
			case "credential_environment":
				connection[field] = "OPEN_TRESTLE_PROVIDER_DIFFERENT"
			case "both authorities":
				connection["brokered_route_authority"] = map[string]any{}
			case "extra field":
				authority["provider_slug"] = "not-go-authority"
			case "null authority":
				connection["opencode_console_authority"] = nil
			case "valid_from":
				authority[field] = "2026-10-30T00:00:00Z"
			case "valid_until":
				authority[field] = "2026-11-02T00:00:00Z"
			case "account_policy_identity":
				authority[field] = strings.Repeat("e", 64)
			case "v1":
				wire["schema_version"] = 1
				delete(wire, "verification_route_record_identity")
			case "v2":
				wire["schema_version"] = 2
			case "v3":
				wire["schema_version"] = 3
			case "v4":
				wire["schema_version"] = 4
			default:
				authority[field] = "other-value"
			}
			policy, err := decodeOpenCodeConsoleStatic(t, inventory, wire)
			if err == nil || policy.Identity() != "" {
				t.Fatal("unbound policy mutation admitted")
			}
		})
	}
}

func TestOpenCodeConsoleV5RetainsGoOpenRouterAndGenericAdmission(t *testing.T) {
	goInventory, goWire := openCodeGoStaticFixture(t, nil)
	goWire["schema_version"] = 5
	if policy, err := decodeOpenCodeConsoleStatic(t, goInventory, goWire); err != nil || policy.ValidateAgainstInventory(goInventory) != nil {
		t.Fatal("v5 Go refused", err)
	}
	witness := privacyFixtureWitness(t)
	inventory := privacyFixtureInventory(t, privacyFixtureManifest(t, witness), false, true)
	wire := privacyFixturePolicy(t, inventory, privacyFixtureAccountIdentity(t, witness.Account), true, 5)
	if policy, err := decodeOpenCodeConsoleStatic(t, inventory, wire); err != nil || policy.ValidateAgainstInventory(inventory) != nil {
		t.Fatal("v5 OpenRouter refused", err)
	}
	genericInventory := privacyFixtureInventory(t, []byte("opaque legacy evidence"), false, false)
	generic := privacyFixturePolicy(t, genericInventory, "", false, 5)
	if policy, err := decodeOpenCodeConsoleStatic(t, genericInventory, generic); err != nil || policy.ValidateAgainstInventory(genericInventory) != nil {
		t.Fatal("v5 generic refused", err)
	}
	for _, version := range []int{1, 2, 3, 4} {
		generic := privacyFixturePolicy(t, genericInventory, "", false, version)
		if version == 1 {
			delete(generic, "verification_route_record_identity")
		}
		generic["connections"].([]any)[0].(map[string]any)["opencode_console_authority"] = nil
		if policy, err := decodeOpenCodeConsoleStatic(t, genericInventory, generic); err == nil || policy.Identity() != "" {
			t.Fatal("historical version ignored Console null authority")
		}
	}
}

func TestOpenCodeConsoleStaticRefusesFreeSelector(t *testing.T) {
	inventory, wire := openCodeConsoleStaticFixture(t, func(encoded []byte) []byte {
		return bytes.ReplaceAll(encoded, []byte("glm-5.3-flash"), []byte("glm-5.3-flash-free"))
	})
	if policy, err := decodeOpenCodeConsoleStatic(t, inventory, wire); err == nil || policy.Identity() != "" {
		t.Fatal("free witness admitted")
	}
}

func TestOpenCodeConsoleWitnessRefusesFreeEvenWithZeroDayDeclaration(t *testing.T) {
	inventory, _ := openCodeConsoleStaticFixture(t, nil)
	for _, projection := range inventory.openCodeConsolePrivacy {
		if projection == (openCodeConsolePrivacyProjection{}) {
			continue
		}
		for _, selector := range []string{"glm-5.3-flash-free", "big-pickle"} {
			witness := projection.witness
			witness.Route.ModelID, witness.Route.EffectiveSelector = selector, selector
			if witness.valid() {
				t.Fatal("free selector made eligible by a zero-day assertion")
			}
		}
	}
}

func TestOpenCodeConsoleAccountRejectsOtherBillingAndPermissionModes(t *testing.T) {
	for _, change := range []struct{ old, new string }{
		{`"billing_mode":"prepaid_balance"`, `"billing_mode":"invoiced_credit"`},
		{`"key_kind":"personal"`, `"key_kind":"service_account"`},
		{`"models_request":true`, `"models_request":false`},
		{`"models_request":true`, `"models_request":null`},
	} {
		inventory, wire := openCodeConsoleStaticFixture(t, func(encoded []byte) []byte {
			changed := strings.Replace(string(encoded), change.old, change.new, 1)
			if changed == string(encoded) {
				t.Fatal("mutation did not reach witness")
			}
			return []byte(changed)
		})
		if policy, err := decodeOpenCodeConsoleStatic(t, inventory, wire); err == nil || policy.Identity() != "" {
			t.Fatal("unreviewed account mode admitted")
		}
	}
}
