package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRuntimePolicyOpenRouterPrivacyWitnessRequired(t *testing.T) {
	for name, manifest := range map[string][]byte{"arbitrary": []byte("arbitrary nonempty evidence"), "unrelated JSON": []byte(`{"benchmark":"approved"}`)} {
		for _, decoded := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/New", true: "/Decode"}[decoded], func(t *testing.T) {
				inventory := privacyFixtureInventory(t, manifest, decoded, true)
				wire := privacyFixturePolicy(t, inventory, strings.Repeat("e", 64), true, 3)
				policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(privacyFixtureJSON(t, wire)), inventory)
				if err == nil || policy.Identity() != "" {
					t.Fatal("profile admitted without a typed privacy witness")
				}
			})
		}
	}
}

func TestRuntimePolicyOpenRouterPrivacyWitnessSyntheticBinding(t *testing.T) {
	witness := privacyFixtureWitness(t)
	manifest := privacyFixtureManifest(t, witness)
	var directIdentity string
	for _, decoded := range []bool{false, true} {
		inventory := privacyFixtureInventory(t, manifest, decoded, true)
		if directIdentity == "" {
			directIdentity = inventory.Identity()
		} else if directIdentity != inventory.Identity() {
			t.Fatal("inventory construction paths differ")
		}
		wire := privacyFixturePolicy(t, inventory, privacyFixtureAccountIdentity(t, witness.Account), true, 3)
		encoded := privacyFixtureJSON(t, wire)
		policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(encoded), inventory)
		if err != nil || policy.ValidateAgainstInventory(inventory) != nil {
			t.Fatalf("synthetic witness refused: %v", err)
		}
		for _, field := range []string{"account_policy_identity", "tenant_id", "repository_id", "provider_slug", "valid_from", "valid_until", "credential_environment"} {
			t.Run(field+map[bool]string{false: "/New", true: "/Decode"}[decoded], func(t *testing.T) {
				var changed map[string]any
				if err := json.Unmarshal(encoded, &changed); err != nil {
					t.Fatal(err)
				}
				connection := changed["connections"].([]any)[0].(map[string]any)
				authority := connection["brokered_route_authority"].(map[string]any)
				switch field {
				case "account_policy_identity":
					authority[field] = strings.Repeat("f", 64)
				case "valid_from":
					authority[field] = "2026-10-02T00:00:00Z"
				case "valid_until":
					authority[field] = "2026-11-02T00:00:00Z"
				case "credential_environment":
					connection[field] = "OPEN_TRESTLE_PROVIDER_ANOTHER"
				default:
					authority[field] = "another-value"
				}
				result, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(privacyFixtureJSON(t, changed)), inventory)
				if err == nil || result.Identity() != "" {
					t.Fatal("policy-only mutation admitted without re-reviewed evidence")
				}
			})
		}
	}
}

func TestOpenRouterSafetyRetentionAccountIdentityVersion(t *testing.T) {
	witness := privacyFixtureWitness(t)
	var account openRouterPrivacyAccount
	if err := json.Unmarshal(privacyFixtureJSON(t, witness.Account), &account); err != nil {
		t.Fatal(err)
	}
	if account.identity() != privacyFixtureAccountIdentity(t, witness.Account) {
		t.Fatal("v2 account identity preimage differs")
	}
	legacy := privacyFixtureDigest(privacyFixtureJSON(t, struct {
		Contract string                       `json:"contract"`
		Version  int                          `json:"version"`
		Account  privacyWitnessAccountFixture `json:"account"`
	}{"open-trestle/openrouter-account-policy", 1, witness.Account}))
	if legacy == account.identity() {
		t.Fatal("v1 account identity gained v2 authority")
	}
	inventory := privacyFixtureInventory(t, privacyFixtureManifest(t, witness), false, true)
	wire := privacyFixturePolicy(t, inventory, legacy, true, 3)
	policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(privacyFixtureJSON(t, wire)), inventory)
	if err == nil || policy.Identity() != "" {
		t.Fatal("v1 account identity admitted")
	}
}

func TestRuntimePolicyOpenRouterSafetyRetentionAdmission(t *testing.T) {
	witness := privacyFixtureWitness(t)
	for name, mutate := range map[string]func(map[string]any){
		"legacy witness":           func(w map[string]any) { w["schema_version"] = 1 },
		"future witness":           func(w map[string]any) { w["schema_version"] = 3 },
		"eligible-only slug scope": func(w map[string]any) { w["provider_slug_scope"] = "all_zdr_eligible_matches" },
		"missing account scope":    func(w map[string]any) { delete(w["account"].(map[string]any), "safety_retention_scope") },
		"null account scope":       func(w map[string]any) { w["account"].(map[string]any)["safety_retention_scope"] = nil },
		"account-only scope":       func(w map[string]any) { w["account"].(map[string]any)["safety_retention_scope"] = "account_only" },
		"missing Google":           func(w map[string]any) { delete(w["account"].(map[string]any), "effective_safety_retention_google") },
		"null Google":              func(w map[string]any) { w["account"].(map[string]any)["effective_safety_retention_google"] = nil },
		"allowed Google":           func(w map[string]any) { w["account"].(map[string]any)["effective_safety_retention_google"] = "allowed" },
		"unknown Google":           func(w map[string]any) { w["account"].(map[string]any)["effective_safety_retention_google"] = "unknown" },
		"missing other":            func(w map[string]any) { delete(w["account"].(map[string]any), "effective_safety_retention_other") },
		"null other":               func(w map[string]any) { w["account"].(map[string]any)["effective_safety_retention_other"] = nil },
		"allowed other":            func(w map[string]any) { w["account"].(map[string]any)["effective_safety_retention_other"] = "allowed" },
		"unknown other":            func(w map[string]any) { w["account"].(map[string]any)["effective_safety_retention_other"] = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			var wire map[string]any
			if err := json.Unmarshal(privacyFixtureJSON(t, witness), &wire); err != nil {
				t.Fatal(err)
			}
			mutate(wire)
			manifest := privacyFixtureJSON(t, map[string]any{"openrouter_privacy": wire})
			var changed privacyWitnessFixture
			if err := json.Unmarshal(privacyFixtureJSON(t, wire), &changed); err != nil {
				t.Fatal(err)
			}
			for _, decoded := range []bool{false, true} {
				inventory := privacyFixtureInventory(t, manifest, decoded, true)
				policyWire := privacyFixturePolicy(t, inventory, privacyFixtureAccountIdentity(t, changed.Account), true, 3)
				policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(privacyFixtureJSON(t, policyWire)), inventory)
				if err == nil || policy.Identity() != "" {
					t.Fatal("unsafe Safety Retention declaration admitted")
				}
			}
		})
	}
}

func TestRuntimePolicyOpenRouterLegacyWitnessCannotGainSafetyRetentionAuthority(t *testing.T) {
	witness := privacyFixtureWitness(t)
	var legacy map[string]any
	if err := json.Unmarshal(privacyFixtureJSON(t, witness), &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["schema_version"] = 1
	legacy["provider_slug_scope"] = "all_zdr_eligible_matches"
	account := legacy["account"].(map[string]any)
	delete(account, "safety_retention_scope")
	delete(account, "effective_safety_retention_google")
	delete(account, "effective_safety_retention_other")
	manifest := privacyFixtureJSON(t, map[string]any{"openrouter_privacy": legacy})
	legacyAccount := struct {
		AuthorityLabel              string                      `json:"authority_label"`
		CredentialReferenceIdentity string                      `json:"credential_reference_identity"`
		ContentLogging              string                      `json:"content_logging"`
		Training                    string                      `json:"training"`
		ReviewEvidence              privacyWitnessSourceFixture `json:"review_evidence"`
	}{witness.Account.AuthorityLabel, witness.Account.CredentialReferenceIdentity, witness.Account.ContentLogging, witness.Account.Training, witness.Account.ReviewEvidence}
	legacyIdentity := privacyFixtureDigest(privacyFixtureJSON(t, struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Account  any    `json:"account"`
	}{"open-trestle/openrouter-account-policy", 1, legacyAccount}))
	for _, decoded := range []bool{false, true} {
		inventory := privacyFixtureInventory(t, manifest, decoded, true)
		now, _ := canonicalPrivacyTime("2026-10-15T00:00:00Z")
		for _, candidate := range inventory.Candidates() {
			if inventory.OpenRouterPrivacyCurrent(candidate.ResolvedRecord().RouteRegistryRecord().Identity(), now) {
				t.Fatal("legacy witness became current strict authority")
			}
		}
		for _, identity := range []string{legacyIdentity, privacyFixtureAccountIdentity(t, witness.Account)} {
			policyWire := privacyFixturePolicy(t, inventory, identity, true, 3)
			policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(privacyFixtureJSON(t, policyWire)), inventory)
			if err == nil || policy.Identity() != "" {
				t.Fatal("legacy witness admitted as strict authority")
			}
		}
		genericInventory := privacyFixtureInventory(t, manifest, decoded, false)
		for _, version := range []int{1, 2} {
			wire := privacyFixturePolicy(t, genericInventory, "", false, version)
			policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(privacyFixtureJSON(t, wire)), genericInventory)
			if err != nil || policy.ValidateAgainstInventory(genericInventory) != nil {
				t.Fatalf("retained legacy witness changed generic v%d admission: %v", version, err)
			}
		}
	}
}

func TestRuntimePolicyOpenRouterPrivacyWitnessRejectsMalformedOrMismatchedSection(t *testing.T) {
	witness := privacyFixtureWitness(t)
	valid := string(privacyFixtureManifest(t, witness))
	cases := map[string]string{
		"top-level array":               `[]`,
		"top-level null":                `null`,
		"duplicate top-level section":   strings.TrimSuffix(valid, "}") + "," + strings.TrimPrefix(valid, "{"),
		"duplicate opaque sibling":      strings.TrimSuffix(valid, "}") + `,"other":{"x":1,"x":2}}`,
		"missing empty-allowed version": strings.Replace(valid, `"model_version":"fixture-version",`, ``, 1),
		"null empty-allowed version":    strings.Replace(valid, `"model_version":"fixture-version"`, `"model_version":null`, 1),
		"null section":                  `{"openrouter_privacy":null}`,
		"unknown section field":         strings.Replace(valid, `"schema_version":2`, `"schema_version":2,"extra":true`, 1),
		"duplicate":                     strings.Replace(valid, `"schema_version":2`, `"schema_version":2,"schema_version":2`, 1),
		"case alias":                    strings.Replace(valid, `"provider_slug_scope"`, `"Provider_slug_scope"`, 1),
		"safety retention alias":        strings.Replace(valid, `"effective_safety_retention_google"`, `"Effective_safety_retention_google"`, 1),
		"duplicate safety retention":    strings.Replace(valid, `"effective_safety_retention_other":"denied"`, `"effective_safety_retention_other":"denied","effective_safety_retention_other":"allowed"`, 1),
		"unknown safety retention":      strings.Replace(valid, `"safety_retention_scope":"effective_account_and_guardrails"`, `"safety_retention_scope":"effective_account_and_guardrails","allow_safety_retention":false`, 1),
		"trailing":                      valid + ` {}`,
		"missing role":                  strings.Replace(valid, `"slug_evidence":`, `"unknown_evidence":`, 1),
		"null role":                     strings.Replace(valid, `"slug_evidence":`+string(privacyFixtureJSON(t, witness.SlugEvidence)), `"slug_evidence":null`, 1),
		"wrong contract":                strings.Replace(valid, `open-trestle/openrouter-privacy-witness`, `other-contract`, 1),
		"wrong schema":                  strings.Replace(valid, `"schema_version":2`, `"schema_version":3`, 1),
		"wrong zone":                    strings.Replace(valid, `"zone":"brokered_remote"`, `"zone":"private_remote"`, 1),
		"wrong provider":                strings.Replace(valid, `"provider_id":"openrouter"`, `"provider_id":"another"`, 1),
		"wrong adapter":                 strings.Replace(valid, `"adapter_id":"adapter-a"`, `"adapter_id":"another"`, 1),
		"wrong connection":              strings.Replace(valid, `"connection_id":"primary/openrouter"`, `"connection_id":"another"`, 1),
		"wrong model":                   strings.Replace(valid, `"model_id":"vendor/model"`, `"model_id":"other/model"`, 1),
		"wrong version":                 strings.Replace(valid, `"model_version":"fixture-version"`, `"model_version":"other-version"`, 1),
		"wrong selector":                strings.Replace(valid, `"effective_selector":"fixture-version"`, `"effective_selector":"vendor/model"`, 1),
		"wrong endpoint":                strings.Replace(valid, `https://openrouter.ai/api/v1`, `https://other.example/v1`, 1),
		"wrong profile":                 strings.Replace(valid, `openrouter_zdr_chat_v1`, `generic`, 1),
		"wrong protocol":                strings.Replace(valid, `openai_chat_completions`, `openai_responses`, 1),
		"wrong auth":                    strings.Replace(valid, `"credential_mode":"bearer"`, `"credential_mode":"none"`, 1),
		"wrong scope":                   strings.Replace(valid, `all_slug_matches`, `one-physical-endpoint`, 1),
		"unaccepted exceptions":         strings.Replace(valid, `"accepted_retention_contract":"openrouter_zdr_with_documented_exceptions"`, `"accepted_retention_contract":"unconditional_non_retention"`, 1),
		"training":                      strings.Replace(valid, `"training":"disabled"`, `"training":"enabled"`, 1),
		"logging":                       strings.Replace(valid, `"content_logging":"disabled"`, `"content_logging":"enabled"`, 1),
		"byok":                          strings.Replace(valid, `"byok":"excluded"`, `"byok":"allowed"`, 1),
		"private endpoint":              strings.Replace(valid, `"private_endpoints":"excluded"`, `"private_endpoints":"allowed"`, 1),
		"tools":                         strings.Replace(valid, `"tools":"excluded"`, `"tools":"allowed"`, 1),
		"plugins":                       strings.Replace(valid, `"plugins":"excluded"`, `"plugins":"allowed"`, 1),
		"url query":                     strings.Replace(valid, `upstream-model-slug-scope`, `upstream-model-slug-scope?token=secret`, 1),
		"url fragment":                  strings.Replace(valid, `upstream-model-slug-scope`, `upstream-model-slug-scope#fragment`, 1),
		"url credentials":               strings.Replace(valid, `https://evidence.fixture.invalid/upstream`, `https://user:secret@evidence.fixture.invalid/upstream`, 1),
		"url plaintext":                 strings.Replace(valid, `https://evidence.fixture.invalid/upstream`, `http://evidence.fixture.invalid/upstream`, 1),
		"empty url":                     strings.Replace(valid, `https://evidence.fixture.invalid/upstream-model-slug-scope`, ``, 1),
		"oversized url":                 strings.Replace(valid, `https://evidence.fixture.invalid/upstream-model-slug-scope`, `https://evidence.fixture.invalid/`+strings.Repeat("a", 2048), 1),
		"oversized label":               strings.Replace(valid, witness.Account.AuthorityLabel, strings.Repeat("a", 257), 1),
		"missing source digest":         strings.Replace(valid, witness.Upstream.Evidence.ContentSHA256, ``, 1),
		"zero source digest":            strings.Replace(valid, witness.Upstream.Evidence.ContentSHA256, strings.Repeat("0", 64), 1),
		"missing source timestamp":      strings.Replace(valid, `"retrieved_at":"2026-09-30T00:00:00Z"`, `"retrieved_at":""`, 1),
		"noncanonical source time":      strings.Replace(valid, `"retrieved_at":"2026-09-30T00:00:00Z"`, `"retrieved_at":"2026-09-30T00:00:00+00:00"`, 1),
		"source after review":           strings.Replace(valid, `"retrieved_at":"2026-09-30T00:00:00Z"`, `"retrieved_at":"2026-10-01T00:00:00Z"`, 1),
		"review after from":             strings.Replace(valid, `"reviewed_at":"2026-09-30T00:00:00Z"`, `"reviewed_at":"2026-10-02T00:00:00Z"`, 1),
		"equal validity":                strings.Replace(valid, `"valid_until":"2026-11-01T00:00:00Z"`, `"valid_until":"2026-10-01T00:00:00Z"`, 1),
	}
	for name, manifest := range cases {
		t.Run(name, func(t *testing.T) {
			inventory := privacyFixtureInventory(t, []byte(manifest), false, true)
			wire := privacyFixturePolicy(t, inventory, privacyFixtureAccountIdentity(t, witness.Account), true, 3)
			policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(privacyFixtureJSON(t, wire)), inventory)
			if err == nil || policy.Identity() != "" {
				t.Fatal("malformed or mismatched privacy witness accepted")
			}
		})
	}
}

func TestRuntimePolicyOpenRouterPrivacyWitnessLegacyOpaqueManifest(t *testing.T) {
	for _, manifest := range [][]byte{[]byte("arbitrary legacy manifest"), []byte(`{"openrouter_privacy":null}`), []byte(`{"openrouter_privacy":{"unknown":true}}`)} {
		for _, decoded := range []bool{false, true} {
			inventory := privacyFixtureInventory(t, manifest, decoded, false)
			for _, version := range []int{1, 2} {
				wire := privacyFixturePolicy(t, inventory, "", false, version)
				policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(privacyFixtureJSON(t, wire)), inventory)
				if err != nil || policy.ValidateAgainstInventory(inventory) != nil {
					t.Fatalf("legacy v%d changed: %v", version, err)
				}
			}
		}
	}
}
