package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// writeLegacyOpenRouterSetup writes a bootstrap directory exactly as the
// earlier reviewed OpenRouter bootstrap did: runtime policy v3, the
// openrouter_zdr_chat_v1 profile with its eight-member authority, and a
// version 2 privacy witness with operator-declared evidence and a review
// window. Every value is a synthetic fixture.
func writeLegacyOpenRouterSetup(t *testing.T, from, until time.Time) string {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	checkout := remoteBootstrapCheckout(t)
	source, err := resolveLocalCheckout(ctx, checkout, "refs/heads/base", "refs/heads/review")
	if err != nil {
		t.Fatal(err)
	}
	stamp := func(at time.Time) string { return at.UTC().Truncate(time.Second).Format(time.RFC3339) }
	reviewed := stamp(from.Add(-time.Hour))
	evidence := func(path string) remoteEvidence {
		return remoteEvidence{URL: "https://evidence.fixture.invalid/" + path, RetrievedAt: reviewed, ContentSHA256: remoteTestDigest}
	}
	type legacyAccount struct {
		AuthorityLabel                 string         `json:"authority_label"`
		CredentialReferenceIdentity    string         `json:"credential_reference_identity"`
		ContentLogging                 string         `json:"content_logging"`
		Training                       string         `json:"training"`
		SafetyRetentionScope           string         `json:"safety_retention_scope"`
		EffectiveSafetyRetentionGoogle string         `json:"effective_safety_retention_google"`
		EffectiveSafetyRetentionOther  string         `json:"effective_safety_retention_other"`
		ReviewEvidence                 remoteEvidence `json:"review_evidence"`
	}
	environment := "OPEN_TRESTLE_PROVIDER_REMOTE_TEST"
	credentialIdentity := remoteDigest([]byte("open-trestle/provider-credential-environment/" + environment))
	account := legacyAccount{"operator declaration by fixture-operator via trestle setup bootstrap; not provider attestation", credentialIdentity, "disabled", "disabled", "effective_account_and_guardrails", "denied", "denied", evidence("account")}
	accountIdentity := remoteAccountIdentity("open-trestle/openrouter-account-policy", 2, account)
	models := map[string]string{"generation": "vendor/generator", "verification": "other/verifier"}
	slugs := map[string]string{"generation": "fixture-upstream/region", "verification": "other-upstream"}
	routes := []map[string]any{}
	for _, role := range []string{"generation", "verification"} {
		route := remoteWitnessRoute{Zone: "brokered_remote", ProviderID: "openrouter", AdapterID: "openrouter-" + role, ConnectionID: "openrouter/" + role, ModelID: models[role], EffectiveSelector: models[role]}
		manifest, _ := json.Marshal(map[string]any{
			"open_trestle_bootstrap_declaration": map[string]any{"contract": "open-trestle/operator-remote-bootstrap-declaration", "schema_version": 1, "declared_by": "fixture-operator", "provider": "openrouter-zdr", "endpoint": "https://openrouter.ai/api/v1", "role": role, "model": models[role], "limitations": "operator declaration, not measured health, provider privacy, account state or service conformance"},
			"openrouter_privacy": map[string]any{
				"contract": "open-trestle/openrouter-privacy-witness", "schema_version": 2, "route": route, "endpoint": "https://openrouter.ai/api/v1", "request_profile": "openrouter_zdr_chat_v1", "protocol": "openai_chat_completions", "credential_mode": "bearer",
				"provider_slug": slugs[role], "provider_slug_scope": "all_slug_matches",
				"upstream":      map[string]any{"retention_contract": "openrouter_zdr_with_documented_exceptions", "training": "disabled", "evidence": evidence(role + "-upstream")},
				"broker":        map[string]any{"retention_contract": "openrouter_zdr_with_documented_exceptions", "evidence": evidence("broker")},
				"slug_evidence": evidence(role + "-slug"), "account": account, "tenant_id": "tenant-remote", "repository_id": "repository-remote",
				"accepted_retention_contract": "openrouter_zdr_with_documented_exceptions", "reviewed_at": reviewed, "valid_from": stamp(from), "valid_until": stamp(until),
				"byok": "excluded", "private_endpoints": "excluded", "tools": "excluded", "plugins": "excluded",
			},
		})
		routes = append(routes, map[string]any{"zone": "brokered_remote", "provider_id": "openrouter", "adapter_id": "openrouter-" + role, "connection_id": "openrouter/" + role, "model_id": models[role], "model_version": "", "max_context_tokens": 128000, "max_output_tokens": 8192, "features": []string{"structured_output"}, "content_logging": "disabled", "pricing_known": true, "input_micro_usd_per_million_tokens": 1000000, "output_micro_usd_per_million_tokens": 2000000, "quality": "tier_1", "registry_revision": 1, "registry_status": "approved", "evidence_manifest_base64": base64.StdEncoding.EncodeToString(manifest), "operational_revision": 1, "health": "healthy", "quota": "available", "performance_revision": 1, "latency_known": false, "p95_latency_milliseconds": 0, "latency_sample_count": 0})
	}
	inventoryBytes, _ := json.Marshal(map[string]any{"schema_version": 1, "routes": routes})
	inventory, err := runtimeconfig.DecodeRouteInventory(ctx, bytes.NewReader(inventoryBytes))
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]string{}
	digests := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		adapter := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()
		records[adapter], digests[adapter] = record.Identity(), record.EvidenceManifestDigest()
	}
	connections := []map[string]any{}
	for _, role := range []string{"generation", "verification"} {
		adapter := "openrouter-" + role
		connections = append(connections, map[string]any{"implementation": "openai_chat_completions", "adapter_id": adapter, "endpoint": "https://openrouter.ai/api/v1", "credential_environment": environment, "request_profile": "openrouter_zdr_chat_v1", "brokered_route_authority": map[string]any{
			"route_record_identity": records[adapter], "evidence_manifest_digest": digests[adapter], "account_policy_identity": accountIdentity, "tenant_id": "tenant-remote", "repository_id": "repository-remote", "provider_slug": slugs[role], "valid_from": stamp(from), "valid_until": stamp(until),
		}})
	}
	reviewPolicy := sha256.Sum256([]byte("open-trestle/remote-model-review-bootstrap/review-policy/v1/openrouter-zdr/distinct-model/no-publication"))
	policyBytes, _ := json.Marshal(map[string]any{"schema_version": 3, "inventory_identity": inventory.Identity(), "review_policy_identity": hex.EncodeToString(reviewPolicy[:]), "verification_route_record_identity": records["openrouter-verification"], "min_context_tokens": 1, "min_output_tokens": 1, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{"brokered_remote"}, "content_logging_allowed": false, "estimated_input_tokens": 1, "max_output_tokens": 4096, "max_cost_micro_usd": 1000000, "pinned_route_record_identity": records["openrouter-generation"], "preferred_route_record_identities": []string{}, "verification_independence": "distinct_model", "publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_model", "publication_block_on_inconclusive": true, "connections": connections})
	policy, err := runtimeconfig.DecodeRuntimePolicy(ctx, bytes.NewReader(policyBytes), inventory)
	if err != nil {
		t.Fatalf("the legacy policy no longer decodes: %v", err)
	}
	review := []string{"trestle", "local-git", "model-review", "--checkout", checkout, "--base", source.base, "--head", source.head, "--repository-authority", "example.test", "--repository-namespace", "private/team", "--repository-name", "sample", "--tenant", "tenant-remote", "--repository", "repository-remote", "--route-inventory", filepath.Join(dir, "routes.json"), "--runtime-policy", filepath.Join(dir, "policy.json"), "--egress", "policy-approved", "--timeout", "10m", "--format", "text"}
	manifestBytes, _ := json.Marshal(remoteBootstrapManifest{Contract: remoteBootstrapContract, Version: 1, Provider: "openrouter-zdr", Inventory: inventory.Identity(), Policy: policy.Identity(), CredentialEnvironments: []string{environment}, ReviewCommand: review})
	for name, content := range map[string][]byte{"routes.json": inventoryBytes, "policy.json": policyBytes, "bootstrap.json": manifestBytes} {
		if err := ensureSetupBootstrapFile(ctx, filepath.Join(dir, name), content); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A directory written by the earlier reviewed bootstrap still reads back:
// check is ready inside its window, refuses after it with a re-run message,
// keeps the reviewed limitations and still reports per-request ZDR.
func TestSetupBootstrapCheckReadsBackALegacyOpenRouterDirectory(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	now := time.Now().UTC()
	current := writeLegacyOpenRouterSetup(t, now.Add(-time.Hour), now.Add(24*time.Hour))
	ready, _ := remoteBootstrapInvoke(t, []string{"check", "--directory", current}, 0)
	if !ready.Ready || ready.Provider != "openrouter-zdr" || ready.DataRetention != "required_per_request" || !slices.Contains(ready.Limitations, "operator_declared_provider_account_and_model_facts_not_verified") || slices.Contains(ready.Limitations, "openrouter_api_reported_model_facts_not_verified") {
		t.Fatalf("legacy directory did not read back as ready: %+v", ready)
	}
	expired := writeLegacyOpenRouterSetup(t, now.Add(-48*time.Hour), now.Add(-time.Hour))
	refused, _ := remoteBootstrapInvoke(t, []string{"check", "--directory", expired}, 4)
	if !slices.Equal(refused.Refused, []string{"privacy_declaration_current"}) || !strings.Contains(strings.Join(refused.Messages, " "), "initialize a new directory") {
		t.Fatalf("an expired legacy window was not refused clearly: %+v", refused)
	}
	resumed := runInitScript(t, remoteBootstrapCheckout(t), []string{"--directory", current}, "1")
	if resumed.code != initExitDone || !initHas(resumed.stdout, "Your declared privacy review window is current") || !initHas(resumed.stdout, "zero data retention required on every request") {
		t.Fatalf("trestle init did not resume the legacy setup: exit=%d\n%s\n%s", resumed.code, resumed.stdout, resumed.stderr)
	}
}
