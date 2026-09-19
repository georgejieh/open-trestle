package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const inventoryIdentityLeakSentinel = "CONFIG_INVENTORY_IDENTITY_SECRET_SENTINEL"

type inventoryIdentityResult struct {
	Contract              string   `json:"contract"`
	SchemaVersion         int      `json:"schema_version"`
	Status                string   `json:"status"`
	InventoryIdentity     string   `json:"inventory_identity"`
	RouteRecordIdentities []string `json:"route_record_identities"`
	RouteCount            int      `json:"route_count"`
}

type shortNilWriter struct{}

func (shortNilWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

type leakingErrorWriter struct{}

func (leakingErrorWriter) Write([]byte) (int, error) {
	return 0, errors.New("writer leaked " + inventoryIdentityLeakSentinel)
}

func TestRunConfigInventoryIdentityReportsOnlyCanonicalIdentities(t *testing.T) {
	document := configIdentityInventoryDocument(t, "local-model-zeta", "local-model-alpha")
	path := writeConfigIdentityProtectedFile(t, "routes.json", document, 0o600)
	expected := decodeConfigIdentityInventory(t, document)
	result, stdout, stderr, code := runConfigIdentityCommand(t, path)
	if code != 0 || stderr != "" {
		t.Fatalf("inventory-identity code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if len(stdout) > 8192 {
		t.Fatalf("inventory-identity stdout length=%d, want <=8192", len(stdout))
	}
	if result.Contract != "open-trestle/route-inventory-identity-result" || result.SchemaVersion != 1 || result.Status != "decoded" {
		t.Fatalf("unexpected identity result header: %#v", result)
	}
	if result.InventoryIdentity != expected.Identity() {
		t.Fatalf("inventory identity=%q, want %q", result.InventoryIdentity, expected.Identity())
	}
	wantRoutes := configIdentityRouteIDs(expected)
	if !reflect.DeepEqual(result.RouteRecordIdentities, wantRoutes) || result.RouteCount != len(wantRoutes) {
		t.Fatalf("route identities/count=(%v,%d), want (%v,%d)", result.RouteRecordIdentities, result.RouteCount, wantRoutes, len(wantRoutes))
	}
	assertCanonicalDigestList(t, append([]string{result.InventoryIdentity}, result.RouteRecordIdentities...))
	for index := 1; index < len(result.RouteRecordIdentities); index++ {
		if result.RouteRecordIdentities[index-1] >= result.RouteRecordIdentities[index] {
			t.Fatalf("route identities not strictly sorted: %v", result.RouteRecordIdentities)
		}
	}
	assertInventoryIdentityNoLeak(t, stdout, path)

	var topStdout bytes.Buffer
	var topStderr bytes.Buffer
	if topCode := run([]string{"config", "inventory-identity", "--route-inventory", path}, &topStdout, &topStderr); topCode != 0 || topStderr.Len() != 0 || topStdout.String() != stdout {
		t.Fatalf("top-level config inventory-identity code=%d stdout=%q stderr=%q", topCode, topStdout.String(), topStderr.String())
	}
}

func TestRunConfigInventoryIdentityChangesWithDecodedInventory(t *testing.T) {
	firstDocument := configIdentityInventoryDocument(t, "local-model-alpha")
	secondDocument := configIdentityInventoryDocument(t, "local-model-beta")
	firstPath := writeConfigIdentityProtectedFile(t, "first-routes.json", firstDocument, 0o600)
	secondPath := writeConfigIdentityProtectedFile(t, "second-routes.json", secondDocument, 0o600)
	first, _, firstStderr, firstCode := runConfigIdentityCommand(t, firstPath)
	second, _, secondStderr, secondCode := runConfigIdentityCommand(t, secondPath)
	if firstCode != 0 || secondCode != 0 || firstStderr != "" || secondStderr != "" {
		t.Fatalf("inventory identity commands failed: first=(%d,%q) second=(%d,%q)", firstCode, firstStderr, secondCode, secondStderr)
	}
	if first.InventoryIdentity == second.InventoryIdentity || reflect.DeepEqual(first.RouteRecordIdentities, second.RouteRecordIdentities) {
		t.Fatalf("changed decoded inventory did not change identities: first=%#v second=%#v", first, second)
	}
}

func TestRunConfigInventoryIdentityRejectsInvalidArgumentsWithoutEcho(t *testing.T) {
	path := writeConfigIdentityProtectedFile(t, "routes.json", configIdentityInventoryDocument(t, "local-model-alpha"), 0o600)
	cases := map[string][]string{
		"missing path":      {"inventory-identity"},
		"empty path":        {"inventory-identity", "--route-inventory", ""},
		"duplicate path":    {"inventory-identity", "--route-inventory", path, "--route-inventory", path},
		"extra argument":    {"inventory-identity", "--route-inventory", path, "extra"},
		"unknown flag":      {"inventory-identity", "--unknown", path},
		"irrelevant policy": {"inventory-identity", "--route-inventory", path, "--runtime-policy", path},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := runConfig(args, &stdout, &stderr)
			if code != 2 || stdout.Len() != 0 {
				t.Fatalf("runConfig(%q) code=%d stdout=%q stderr=%q, want usage failure", args, code, stdout.String(), stderr.String())
			}
			assertInventoryIdentityNoLeak(t, stderr.String(), path)
		})
	}
}

func TestRunConfigInventoryIdentityFailsClosedForInvalidProtectedInputs(t *testing.T) {
	valid := configIdentityInventoryDocument(t, "local-model-alpha")
	cases := map[string]struct {
		content []byte
		mode    os.FileMode
		missing bool
	}{
		"missing":   {missing: true},
		"empty":     {content: nil, mode: 0o600},
		"malformed": {content: []byte(`{"schema_version":1,"routes":[` + inventoryIdentityLeakSentinel), mode: 0o600},
		"oversized": {content: bytes.Repeat([]byte{' '}, (8<<20)+1), mode: 0o600},
		"unsafe":    {content: valid, mode: 0o666},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name+"-"+inventoryIdentityLeakSentinel+".json")
			if !test.missing {
				if err := os.WriteFile(path, test.content, 0o600); err != nil {
					t.Fatal(err)
				}
				configIdentityChmod(t, path, test.mode)
			}
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := runConfig([]string{"inventory-identity", "--route-inventory", path}, &stdout, &stderr)
			if code != 1 || stdout.Len() != 0 {
				t.Fatalf("invalid protected input code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			assertInventoryIdentityNoLeak(t, stderr.String(), path)
		})
	}
}

func TestRunConfigInventoryIdentityTreatsIncompleteStdoutAsFailure(t *testing.T) {
	path := writeConfigIdentityProtectedFile(t, "routes.json", configIdentityInventoryDocument(t, "local-model-alpha"), 0o600)
	for name, writer := range map[string]io.Writer{
		"short nil-error writer": shortNilWriter{},
		"failing writer":         leakingErrorWriter{},
	} {
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer
			code := runConfig([]string{"inventory-identity", "--route-inventory", path}, writer, &stderr)
			if code != 1 {
				t.Fatalf("writer failure code=%d stderr=%q", code, stderr.String())
			}
			assertInventoryIdentityNoLeak(t, stderr.String(), path)
		})
	}
}

func configIdentityInventoryDocument(t *testing.T, models ...string) []byte {
	t.Helper()
	if len(models) == 0 {
		models = []string{"local-model-alpha"}
	}
	routes := make([]string, 0, len(models))
	for index, model := range models {
		manifest := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"purpose":"identity-only","sentinel":"%s-%d"}`, inventoryIdentityLeakSentinel, index)))
		routes = append(routes, fmt.Sprintf(`{"zone":"local","provider_id":"openai","adapter_id":"openai-responses-%d","connection_id":"primary-local-%d","model_id":%q,"model_version":"2026-identity","max_context_tokens":128000,"max_output_tokens":8192,"features":["structured_output"],"content_logging":"disabled","pricing_known":false,"input_micro_usd_per_million_tokens":0,"output_micro_usd_per_million_tokens":0,"quality":"tier_1","registry_revision":7,"registry_status":"pending","evidence_manifest_base64":%q,"operational_revision":9,"health":"unknown","quota":"unknown","performance_revision":11,"latency_known":false,"p95_latency_milliseconds":0,"latency_sample_count":0}`, index+1, index+1, model, manifest))
	}
	return []byte(`{"schema_version":1,"routes":[` + strings.Join(routes, ",") + `]}`)
}

func writeConfigIdentityProtectedFile(t *testing.T, name string, content []byte, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	configIdentityChmod(t, dir, 0o700)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	configIdentityChmod(t, path, mode)
	return path
}

func configIdentityChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func decodeConfigIdentityInventory(t *testing.T, document []byte) runtimeconfig.RouteInventory {
	t.Helper()
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}

func configIdentityRouteIDs(inventory runtimeconfig.RouteInventory) []string {
	candidates := inventory.Candidates()
	ids := make([]string, len(candidates))
	for index, candidate := range candidates {
		ids[index] = candidate.ResolvedRecord().RouteRegistryRecord().Identity()
	}
	return ids
}

func runConfigIdentityCommand(t *testing.T, path string) (inventoryIdentityResult, string, string, int) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runConfig([]string{"inventory-identity", "--route-inventory", path}, &stdout, &stderr)
	if code != 0 {
		return inventoryIdentityResult{}, stdout.String(), stderr.String(), code
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fields); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		t.Fatalf("identity result is not one JSON object: stdout=%q err=%v", stdout.String(), err)
	}
	wantKeys := []string{"contract", "schema_version", "status", "inventory_identity", "route_record_identities", "route_count"}
	if len(fields) != len(wantKeys) {
		t.Fatalf("identity result keys=%v, want exactly %v", mapKeys(fields), wantKeys)
	}
	for _, key := range wantKeys {
		if _, ok := fields[key]; !ok {
			t.Fatalf("identity result missing key %q in %v", key, mapKeys(fields))
		}
	}
	var result inventoryIdentityResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("identity result decode: %v", err)
	}
	return result, stdout.String(), stderr.String(), code
}

func assertCanonicalDigestList(t *testing.T, values []string) {
	t.Helper()
	for _, value := range values {
		if len(value) != 64 || strings.ToLower(value) != value {
			t.Fatalf("noncanonical digest %q", value)
		}
		for _, character := range value {
			if character < '0' || character > '9' && character < 'a' || character > 'f' {
				t.Fatalf("nonhex digest %q", value)
			}
		}
	}
}

func assertInventoryIdentityNoLeak(t *testing.T, output, path string) {
	t.Helper()
	for _, secret := range []string{inventoryIdentityLeakSentinel, path, filepath.Base(path), "local-model", "provider_id", "adapter_id", "connection_id", "credential", "OPEN_TRESTLE_PROVIDER", "http://", "https://"} {
		if secret != "" && strings.Contains(output, secret) {
			t.Fatalf("output leaked %q in %q", secret, output)
		}
	}
}

func mapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
