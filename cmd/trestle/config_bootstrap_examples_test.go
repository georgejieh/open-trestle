package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type bootstrapInventoryIdentityResult struct {
	Contract              string   `json:"contract"`
	SchemaVersion         int      `json:"schema_version"`
	Status                string   `json:"status"`
	InventoryIdentity     string   `json:"inventory_identity"`
	RouteRecordIdentities []string `json:"route_record_identities"`
	RouteCount            int      `json:"route_count"`
}

func TestPublishedRouteInventoryIdentitySchemaIsStrictStructuralProjection(t *testing.T) {
	path := filepath.Join("..", "..", "schemas", "runtime", "route-inventory-identity-result-v1.schema.json")
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(encoded, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" || schema["$id"] != "urn:open-trestle:schema:runtime:route-inventory-identity-result:v1" || schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatalf("schema header is not the strict published object contract: %#v", schema)
	}
	wantRequired := []string{"contract", "schema_version", "status", "inventory_identity", "route_record_identities", "route_count"}
	if !sameStringSet(bootstrapStringSlice(t, schema["required"]), wantRequired) {
		t.Fatalf("required fields=%v, want exactly %v", schema["required"], wantRequired)
	}
	properties := bootstrapObject(t, schema["properties"])
	if len(properties) != len(wantRequired) {
		t.Fatalf("schema properties=%v, want exactly %v", bootstrapMapKeys(properties), wantRequired)
	}
	if bootstrapObject(t, properties["contract"])["const"] != "open-trestle/route-inventory-identity-result" || bootstrapObject(t, properties["schema_version"])["const"] != float64(1) || bootstrapObject(t, properties["status"])["const"] != "decoded" {
		t.Fatalf("schema const properties are wrong: %#v", properties)
	}
	assertBootstrapDigestProperty(t, schema, properties["inventory_identity"])
	routeIDs := bootstrapObject(t, properties["route_record_identities"])
	if routeIDs["type"] != "array" || routeIDs["minItems"] != float64(1) || routeIDs["maxItems"] != float64(64) || routeIDs["uniqueItems"] != true {
		t.Fatalf("route_record_identities bounds are wrong: %#v", routeIDs)
	}
	assertBootstrapDigestProperty(t, schema, bootstrapObject(t, routeIDs["items"]))
	routeCount := bootstrapObject(t, properties["route_count"])
	if routeCount["type"] != "integer" || routeCount["minimum"] != float64(1) || routeCount["maximum"] != float64(64) {
		t.Fatalf("route_count bounds are wrong: %#v", routeCount)
	}
	for name := range properties {
		for _, forbidden := range []string{"authority", "grant", "witness", "credential", "endpoint", "path", "environment"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("identity schema exposes forbidden data field %q", name)
			}
		}
	}
}

func TestLocalModelReviewExamplesBindThroughInventoryIdentityCommand(t *testing.T) {
	routesPath := filepath.Join("..", "..", "examples", "local-model-review", "routes.json")
	policyPath := filepath.Join("..", "..", "examples", "local-model-review", "runtime-policy.json")
	metadata := bootstrapRunInventoryIdentity(t, routesPath)
	if metadata.RouteCount < 1 || metadata.RouteCount > 64 || len(metadata.RouteRecordIdentities) != metadata.RouteCount {
		t.Fatalf("identity metadata route count mismatch: %#v", metadata)
	}
	assertCanonicalDigestList(t, append([]string{metadata.InventoryIdentity}, metadata.RouteRecordIdentities...))

	routeDocument := bootstrapReadObject(t, routesPath)
	assertLocalModelReviewRouteExampleShape(t, routeDocument, metadata.RouteCount)
	policyDocument := bootstrapReadObject(t, policyPath)
	assertLocalModelReviewPolicyExampleShape(t, policyDocument)
	if policyDocument["inventory_identity"] != metadata.InventoryIdentity {
		t.Fatal("shipped example policy must already bind the decoded inventory identity")
	}
	boundPolicyPath := policyPath

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runConfig([]string{"validate", "--route-inventory", routesPath, "--runtime-policy", boundPolicyPath}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("config validate examples code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var validation struct {
		Contract          string `json:"contract"`
		Status            string `json:"status"`
		InventoryIdentity string `json:"inventory_identity"`
		RouteCount        int    `json:"route_count"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &validation); err != nil {
		t.Fatalf("decode validation output: %v", err)
	}
	if validation.Contract != "open-trestle/runtime-configuration-validation-result" || validation.Status != "valid" || validation.InventoryIdentity != metadata.InventoryIdentity || validation.RouteCount != metadata.RouteCount {
		t.Fatalf("validation output did not bind identity metadata: %#v", validation)
	}

	if bootstrapProtectedOwnershipSupported() {
		inventory, err := runtimeconfig.LoadProtectedRouteInventory(context.Background(), routesPath)
		if err != nil || inventory.Identity() != metadata.InventoryIdentity {
			t.Fatalf("protected route inventory roundtrip=(%#v,%v), want %q", inventory, err, metadata.InventoryIdentity)
		}
		protectedInventory, protectedPolicy, err := runtimeconfig.LoadProtectedConfiguration(context.Background(), routesPath, boundPolicyPath)
		if err != nil || protectedInventory.Identity() != metadata.InventoryIdentity || protectedPolicy.InventoryIdentity() != metadata.InventoryIdentity || len(protectedPolicy.Connections()) == 0 {
			t.Fatalf("protected configuration roundtrip failed: inventory=%#v policy=%#v err=%v", protectedInventory, protectedPolicy, err)
		}
	}
}

func TestLocalModelReviewDocsTeachBootstrapWithoutReadinessClaims(t *testing.T) {
	localDoc := string(mustReadBootstrapFile(t, filepath.Join("..", "..", "docs", "local-model-review.md")))
	setupDoc := string(mustReadBootstrapFile(t, filepath.Join("..", "..", "docs", "setup.md")))
	readme := string(mustReadBootstrapFile(t, filepath.Join("..", "..", "README.md")))
	localDoc = strings.Join(strings.Fields(strings.ReplaceAll(localDoc, "\\\n", " ")), " ")
	setupDoc = strings.Join(strings.Fields(strings.ReplaceAll(setupDoc, "\\\n", " ")), " ")
	if strings.Contains(localDoc, "ROOT_BINDING_REQUIRED") {
		t.Fatal("published docs must not retain temporary root binding instructions")
	}
	for _, token := range []string{
		"trestle config inventory-identity --route-inventory",
		"inventory_identity",
		"trestle config validate --route-inventory",
		"OpenAI Responses",
		"/v1/responses",
		"already structurally bound",
	} {
		if !strings.Contains(localDoc, token) {
			t.Fatalf("docs/local-model-review.md does not mention %q", token)
		}
	}
	lowerLocalDoc := strings.ToLower(localDoc)
	if !strings.Contains(lowerLocalDoc, "no provider calls") && !strings.Contains(lowerLocalDoc, "does not call providers") && !strings.Contains(lowerLocalDoc, "do not call the provider") {
		t.Fatal("docs/local-model-review.md does not state that identity and validation make no provider calls")
	}
	for _, token := range []string{"live health", "policy binding"} {
		if !strings.Contains(lowerLocalDoc, token) {
			t.Fatalf("docs/local-model-review.md does not preserve boundary concept %q", token)
		}
	}
	if !strings.Contains(lowerLocalDoc, "does not publish") && !strings.Contains(lowerLocalDoc, "no publication") {
		t.Fatal("docs/local-model-review.md does not preserve the no-publication boundary")
	}
	if !strings.Contains(setupDoc, "trestle config inventory-identity --route-inventory") || !strings.Contains(setupDoc, "trestle config validate --route-inventory") {
		t.Fatal("docs/setup.md does not link the inventory identity bootstrap to existing config validate")
	}
	if !strings.Contains(readme, "docs/local-model-review.md") || !strings.Contains(readme, "The static `local-git inspect`, `local-git change`, and deterministic `local-git review` commands support verified loose objects only.") {
		t.Fatal("README.md does not keep the model-review link and explicit static-command loose-only scope")
	}
}

func bootstrapRunInventoryIdentity(t *testing.T, routesPath string) bootstrapInventoryIdentityResult {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runConfig([]string{"inventory-identity", "--route-inventory", routesPath}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("inventory-identity examples code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if len(stdout.Bytes()) > 8192 {
		t.Fatalf("inventory-identity example output is too large: %d", len(stdout.Bytes()))
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	if err := decoder.Decode(&fields); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		t.Fatalf("inventory-identity output is not one JSON object: %q err=%v", stdout.String(), err)
	}
	wantKeys := []string{"contract", "schema_version", "status", "inventory_identity", "route_record_identities", "route_count"}
	if len(fields) != len(wantKeys) {
		t.Fatalf("identity result keys=%v, want %v", bootstrapMapKeys(fields), wantKeys)
	}
	for _, key := range wantKeys {
		if _, ok := fields[key]; !ok {
			t.Fatalf("identity result missing key %q in %v", key, bootstrapMapKeys(fields))
		}
	}
	var result bootstrapInventoryIdentityResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Contract != "open-trestle/route-inventory-identity-result" || result.SchemaVersion != 1 || result.Status != "decoded" {
		t.Fatalf("unexpected identity result: %#v", result)
	}
	return result
}

func assertLocalModelReviewRouteExampleShape(t *testing.T, document map[string]any, count int) {
	t.Helper()
	if document["schema_version"] != float64(1) {
		t.Fatalf("routes schema_version=%#v", document["schema_version"])
	}
	routes, ok := document["routes"].([]any)
	if !ok || len(routes) != count || len(routes) == 0 || len(routes) > 64 {
		t.Fatalf("routes count=%#v, metadata count=%d", document["routes"], count)
	}
	for index, raw := range routes {
		route := bootstrapObject(t, raw)
		providerID, namedProvider := route["provider_id"].(string)
		if route["zone"] != "local" || !namedProvider || providerID == "" || route["adapter_id"] != "openai-responses" || route["content_logging"] != "unknown" {
			t.Fatalf("route %d is not a local OpenAI Responses declaration: %#v", index, route)
		}
		if route["pricing_known"] != false || route["health"] != "unknown" || route["quota"] != "unknown" || route["latency_known"] != false || route["p95_latency_milliseconds"] != float64(0) || route["latency_sample_count"] != float64(0) {
			t.Fatalf("route %d claims measured operational readiness: %#v", index, route)
		}
		manifest, err := base64.StdEncoding.Strict().DecodeString(route["evidence_manifest_base64"].(string))
		if err != nil || !strings.Contains(strings.ToLower(string(manifest)), "illustrative") || strings.Contains(strings.ToLower(string(manifest)), "certified") {
			t.Fatalf("route %d evidence manifest is not an explicit illustrative declaration: %q err=%v", index, manifest, err)
		}
	}
}

func assertLocalModelReviewPolicyExampleShape(t *testing.T, document map[string]any) {
	t.Helper()
	if document["schema_version"] != float64(1) {
		t.Fatalf("policy schema_version=%#v", document["schema_version"])
	}
	if !reflect.DeepEqual(bootstrapStringSlice(t, document["allowed_zones"]), []string{"local"}) {
		t.Fatalf("policy allowed_zones=%#v, want local only", document["allowed_zones"])
	}
	if document["pinned_route_record_identity"] != "" || len(bootstrapStringSlice(t, document["preferred_route_record_identities"])) != 0 {
		t.Fatalf("policy invented route pins or preferences before binding: %#v %#v", document["pinned_route_record_identity"], document["preferred_route_record_identities"])
	}
	connections, ok := document["connections"].([]any)
	if !ok || len(connections) != 1 {
		t.Fatalf("policy connections=%#v, want one local OpenAI Responses endpoint", document["connections"])
	}
	connection := bootstrapObject(t, connections[0])
	if connection["implementation"] != "openai_responses" || connection["adapter_id"] != "openai-responses" {
		t.Fatalf("connection does not name the supported Responses adapter: %#v", connection)
	}
	endpoint, ok := connection["endpoint"].(string)
	parsed, err := url.Parse(endpoint)
	var address net.IP
	if parsed != nil {
		address = net.ParseIP(parsed.Hostname())
	}
	if !ok || err != nil || parsed == nil || parsed.String() != endpoint || parsed.Scheme != "http" || address == nil || !address.IsLoopback() || parsed.Path != "/v1" || parsed.RawQuery != "" || parsed.Fragment != "" {
		t.Fatalf("endpoint %q is not the explicit loopback OpenAI-compatible /v1 base for Responses", endpoint)
	}
	credential, ok := connection["credential_environment"].(string)
	if !ok || !strings.HasPrefix(credential, "OPEN_TRESTLE_PROVIDER_") || strings.Contains(strings.ToLower(credential), "sk-") || strings.Contains(strings.ToLower(fmt.Sprint(document)), "sk-") {
		t.Fatalf("example appears to contain a real credential reference: %#v", connection)
	}
}

func writeBoundBootstrapPolicy(t *testing.T, policy map[string]any, inventoryIdentity string) string {
	t.Helper()
	current, ok := policy["inventory_identity"].(string)
	if !ok || current == "" {
		t.Fatalf("policy inventory_identity is missing: %#v", policy["inventory_identity"])
	}
	if current != strings.Repeat("0", 64) && current != inventoryIdentity {
		t.Fatalf("policy inventory_identity=%q, want placeholder or %q", current, inventoryIdentity)
	}
	clone := make(map[string]any, len(policy))
	for key, value := range policy {
		clone[key] = value
	}
	clone["inventory_identity"] = inventoryIdentity
	encoded, err := json.Marshal(clone)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "runtime-policy.bound.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertBootstrapDigestProperty(t *testing.T, schema map[string]any, raw any) {
	t.Helper()
	property := bootstrapObject(t, raw)
	if property["pattern"] == "^[0-9a-f]{64}$" {
		return
	}
	if property["$ref"] != "#/$defs/digest" {
		t.Fatalf("digest property does not use lowercase hex64 pattern or digest ref: %#v", property)
	}
	defs := bootstrapObject(t, schema["$defs"])
	digest := bootstrapObject(t, defs["digest"])
	if digest["type"] != "string" || digest["pattern"] != "^[0-9a-f]{64}$" {
		t.Fatalf("digest definition is not lowercase hex64: %#v", digest)
	}
}

func bootstrapReadObject(t *testing.T, path string) map[string]any {
	t.Helper()
	encoded := mustReadBootstrapFile(t, path)
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		t.Fatalf("read JSON object %s: %v", path, err)
	}
	return document
}

func mustReadBootstrapFile(t *testing.T, path string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func bootstrapObject(t *testing.T, raw any) map[string]any {
	t.Helper()
	object, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("value is not an object: %#v", raw)
	}
	return object
}

func bootstrapStringSlice(t *testing.T, raw any) []string {
	t.Helper()
	values, ok := raw.([]any)
	if !ok {
		t.Fatalf("value is not an array: %#v", raw)
	}
	out := make([]string, len(values))
	for index, value := range values {
		out[index], ok = value.(string)
		if !ok {
			t.Fatalf("array contains non-string value: %#v", values)
		}
	}
	return out
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[string]int, len(left))
	for _, value := range left {
		seen[value]++
	}
	for _, value := range right {
		seen[value]--
		if seen[value] < 0 {
			return false
		}
	}
	return true
}

func bootstrapMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

func bootstrapProtectedOwnershipSupported() bool {
	switch runtime.GOOS {
	case "aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios", "linux", "netbsd", "openbsd", "solaris":
		return true
	default:
		return false
	}
}

func TestConfigInventoryIdentityBootstrapsUnboundPolicy(t *testing.T) {
	routesPath := filepath.Join("..", "..", "examples", "local-model-review", "routes.json")
	policyPath := filepath.Join("..", "..", "examples", "local-model-review", "runtime-policy.json")
	policy := bootstrapReadObject(t, policyPath)
	policy["inventory_identity"] = strings.Repeat("0", 64)
	unbound := writeBoundBootstrapPolicy(t, policy, strings.Repeat("0", 64))
	var stdout, stderr bytes.Buffer
	if code := runConfig([]string{"validate", "--route-inventory", routesPath, "--runtime-policy", unbound}, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatalf("unbound policy code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	metadata := bootstrapRunInventoryIdentity(t, routesPath)
	bound := writeBoundBootstrapPolicy(t, policy, metadata.InventoryIdentity)
	stdout.Reset()
	stderr.Reset()
	if code := runConfig([]string{"validate", "--route-inventory", routesPath, "--runtime-policy", bound}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("CLI-bound policy code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result["status"] != "valid" || result["inventory_identity"] != metadata.InventoryIdentity {
		t.Fatalf("CLI-bound validation result=%v error=%v", result, err)
	}
}
