package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunConfigValidatesExactInventoryPolicyPair(t *testing.T) {
	root := t.TempDir()
	inventoryPath := filepath.Join(root, "inventory.json")
	policyPath := filepath.Join(root, "policy.json")
	manifest := base64.StdEncoding.EncodeToString([]byte(`{"benchmark":"approved"}`))
	inventoryDocument := fmt.Sprintf(`{"schema_version":1,"routes":[{"zone":"private_remote","provider_id":"openai","adapter_id":"openai-responses","connection_id":"primary/openai","model_id":"model-a","model_version":"2026-01","max_context_tokens":128000,"max_output_tokens":8192,"features":["structured_output"],"content_logging":"disabled","pricing_known":true,"input_micro_usd_per_million_tokens":1000,"output_micro_usd_per_million_tokens":2000,"quality":"tier_3","registry_revision":7,"registry_status":"approved","evidence_manifest_base64":"%s","operational_revision":9,"health":"healthy","quota":"available","performance_revision":11,"latency_known":true,"p95_latency_milliseconds":2500,"latency_sample_count":100}]}`, manifest)
	if err := os.WriteFile(inventoryPath, []byte(inventoryDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), file)
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	record := inventory.Candidates()[0].ResolvedRecord().RouteRegistryRecord().Identity()
	policyDocument := fmt.Sprintf(`{"schema_version":1,"inventory_identity":"%s","review_policy_identity":"%s","min_context_tokens":32000,"min_output_tokens":4096,"required_features":["structured_output"],"classification":"confidential","allowed_zones":["private_remote"],"content_logging_allowed":false,"estimated_input_tokens":8000,"max_output_tokens":4096,"max_cost_micro_usd":100000,"pinned_route_record_identity":"","preferred_route_record_identities":["%s"],"verification_independence":"distinct_provider","publication_minimum_severity":"medium","publication_max_inline_findings":20,"publication_minimum_independence":"distinct_provider","publication_block_on_inconclusive":true,"connections":[{"implementation":"openai_responses","adapter_id":"openai-responses","endpoint":"https://api.openai.com/v1","credential_environment":"OPEN_TRESTLE_PROVIDER_OPENAI_PRIMARY"}]}`, inventory.Identity(), strings.Repeat("a", 64), record)
	configuration, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), strings.NewReader(policyDocument), inventory)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(policyDocument), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runConfig([]string{"validate", "--route-inventory", inventoryPath, "--runtime-policy", policyPath}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), `"contract":"open-trestle/runtime-configuration-validation-result"`) || !strings.Contains(stdout.String(), `"schema_version":1`) || !strings.Contains(stdout.String(), `"status":"valid"`) || strings.Contains(stdout.String(), "OPEN_TRESTLE_PROVIDER") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || len(result) != 8 || result["inventory_identity"] != inventory.Identity() || result["runtime_policy_identity"] != configuration.Identity() || result["review_policy_identity"] != strings.Repeat("a", 64) || result["route_count"] != float64(1) || result["connection_count"] != float64(1) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	badPolicyPath := filepath.Join(root, "policy-bad-endpoint.json")
	for _, endpoint := range []string{"http://example.com/v1", "https://example.com:/v1"} {
		badPolicy := strings.Replace(policyDocument, "https://api.openai.com/v1", endpoint, 1)
		if err := os.WriteFile(badPolicyPath, []byte(badPolicy), 0o600); err != nil {
			t.Fatal(err)
		}
		stdout.Reset()
		stderr.Reset()
		if code := runConfig([]string{"validate", "--route-inventory", inventoryPath, "--runtime-policy", badPolicyPath}, &stdout, &stderr); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid runtime policy") {
			t.Fatalf("unsafe endpoint %q code=%d stdout=%q stderr=%q", endpoint, code, stdout.String(), stderr.String())
		}
	}
	stdout.Reset()
	stderr.Reset()
	if code := runConfig([]string{"validate", "--route-inventory", inventoryPath, "--runtime-policy", inventoryPath}, &stdout, &stderr); code != 1 {
		t.Fatalf("invalid code=%d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"config", "validate", "--route-inventory", inventoryPath, "--runtime-policy", policyPath}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("top-level code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
