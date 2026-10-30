package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func configBindTemplate(endpoint string) []byte {
	return []byte(fmt.Sprintf(`{"schema_version":1,"inventory_identity":"","review_policy_identity":"%s","min_context_tokens":32000,"min_output_tokens":4096,"required_features":["structured_output"],"classification":"confidential","allowed_zones":["local"],"content_logging_allowed":false,"estimated_input_tokens":8000,"max_output_tokens":4096,"max_cost_micro_usd":100000,"pinned_route_record_identity":"","preferred_route_record_identities":[],"verification_independence":"distinct_provider","publication_minimum_severity":"medium","publication_max_inline_findings":19,"publication_minimum_independence":"distinct_provider","publication_block_on_inconclusive":true,"connections":[{"implementation":"openai_responses","adapter_id":"openai-responses-1","endpoint":%q,"credential_environment":"OPEN_TRESTLE_PROVIDER_BIND_A"},{"implementation":"openai_responses","adapter_id":"openai-responses-2","endpoint":%q,"credential_environment":"OPEN_TRESTLE_PROVIDER_BIND_B"}]}`, strings.Repeat("a", 64), endpoint, endpoint))
}

func configBindArgs(inventoryPath, templatePath string) []string {
	return []string{"bind", "--route-inventory", inventoryPath, "--runtime-policy-template", templatePath, "--generation-adapter", "openai-responses-1", "--verification-adapter", "openai-responses-2"}
}

func TestRunConfigBindEmitsCanonicalPolicyWithoutApprovingOrContactingRoutes(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("OPEN_TRESTLE_PROVIDER_BIND_A", "")
	t.Setenv("OPEN_TRESTLE_PROVIDER_BIND_B", "")
	inventoryBytes := bytes.Replace(configIdentityInventoryDocument(t, "local-model-generation", "local-model-verification"),
		[]byte(`"provider_id":"openai","adapter_id":"openai-responses-2"`),
		[]byte(`"provider_id":"verifier","adapter_id":"openai-responses-2"`), 1)
	templateBytes := configBindTemplate(server.URL + "/v1")
	inventoryPath := writeConfigIdentityProtectedFile(t, "routes.json", inventoryBytes, 0o600)
	templatePath := writeConfigIdentityProtectedFile(t, "template.json", templateBytes, 0o600)
	inventory := decodeConfigIdentityInventory(t, inventoryBytes)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"config", "bind", "--route-inventory", inventoryPath, "--runtime-policy-template", templatePath, "--generation-adapter", "openai-responses-1", "--verification-adapter", "openai-responses-2"}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("bind code=%d stderr=%q", code, stderr.String())
	}
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(stdout.Bytes()), inventory)
	if err != nil || policy.ValidateAgainstInventory(inventory) != nil {
		t.Fatalf("canonical policy decode: %v", err)
	}
	var document map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		t.Fatalf("stdout must contain exactly one policy JSON: %v", err)
	}
	var version int
	if err := json.Unmarshal(document["schema_version"], &version); err != nil || version != 2 {
		t.Fatal("output policy must be schema v2")
	}
	ids := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		reference := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		ids[reference.AdapterID()] = record.Identity()
		if record.Status() != provider.RouteRegistryPending || candidate.OperationalState().Health() != provider.RouteHealthUnknown || candidate.OperationalState().Quota() != provider.RouteQuotaUnknown {
			t.Fatal("binding must not infer approval or readiness")
		}
	}
	pinned, ok := policy.Ranking().PinnedRoute()
	if !ok || pinned.AdapterID() != "openai-responses-1" || policy.InventoryIdentity() != inventory.Identity() || policy.VerificationRouteRecordIdentity() != ids["openai-responses-2"] {
		t.Fatal("output did not bind selected inventory records")
	}
	var pin string
	if err := json.Unmarshal(document["pinned_route_record_identity"], &pin); err != nil || pin != ids["openai-responses-1"] {
		t.Fatal("output pin does not identify the generation record")
	}
	var template map[string]json.RawMessage
	if err := json.Unmarshal(templateBytes, &template); err != nil {
		t.Fatal(err)
	}
	for key, expected := range template {
		if key == "schema_version" || key == "inventory_identity" || key == "pinned_route_record_identity" {
			continue
		}
		if !bytes.Equal(document[key], expected) {
			t.Fatalf("unrelated template field changed: %s", key)
		}
	}
	if len(document) != len(template)+1 {
		t.Fatal("output contains fields other than the policy schema")
	}
	pair, err := runtimecatalog.ResolveLocalGenerationRoutePair(policy, inventory)
	if err == nil || pair.Identity() != "" {
		t.Fatal("pending inventory became executable after structural binding")
	}
	for path, expected := range map[string][]byte{inventoryPath: inventoryBytes, templatePath: templateBytes} {
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("binding changed a configuration input")
		}
	}
	if requests.Load() != 0 {
		t.Fatal("binding contacted a provider")
	}
}

func TestRunConfigBindRefusesInvalidInputsWithoutStdoutOrContact(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	inventory := configIdentityInventoryDocument(t, "local-model-generation", "local-model-verification")
	template := configBindTemplate(server.URL + "/v1")
	cases := map[string]struct {
		inventory    []byte
		template     []byte
		generation   string
		verification string
	}{
		"same provider":         {inventory, template, "openai-responses-1", "openai-responses-2"},
		"same adapter":          {inventory, template, "openai-responses-1", "openai-responses-1"},
		"missing generation":    {inventory, template, "absent", "openai-responses-2"},
		"missing verification":  {inventory, template, "openai-responses-1", "absent"},
		"malformed template":    {inventory, []byte("{" + inventoryIdentityLeakSentinel), "openai-responses-1", "openai-responses-2"},
		"unknown template":      {inventory, bytes.Replace(template, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1), "openai-responses-1", "openai-responses-2"},
		"duplicate template":    {inventory, bytes.Replace(template, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1), "openai-responses-1", "openai-responses-2"},
		"null template":         {inventory, []byte("null"), "openai-responses-1", "openai-responses-2"},
		"null template field":   {inventory, bytes.Replace(template, []byte(`"inventory_identity":""`), []byte(`"inventory_identity":null`), 1), "openai-responses-1", "openai-responses-2"},
		"trailing template":     {inventory, append(append([]byte(nil), template...), []byte(" {}")...), "openai-responses-1", "openai-responses-2"},
		"oversize template":     {inventory, bytes.Repeat([]byte{' '}, 1<<20), "openai-responses-1", "openai-responses-2"},
		"conflicting inventory": {inventory, bytes.Replace(template, []byte(`"inventory_identity":""`), []byte(`"inventory_identity":"`+strings.Repeat("f", 64)+`"`), 1), "openai-responses-1", "openai-responses-2"},
		"conflicting pin":       {inventory, bytes.Replace(template, []byte(`"pinned_route_record_identity":""`), []byte(`"pinned_route_record_identity":"`+strings.Repeat("f", 64)+`"`), 1), "openai-responses-1", "openai-responses-2"},
		"conflicting verifier":  {inventory, bytes.Replace(template, []byte(`"schema_version":1`), []byte(`"schema_version":2,"verification_route_record_identity":"`+strings.Repeat("f", 64)+`"`), 1), "openai-responses-1", "openai-responses-2"},
		"malformed inventory":   {[]byte("{" + inventoryIdentityLeakSentinel), template, "openai-responses-1", "openai-responses-2"},
		"duplicate inventory":   {bytes.Replace(inventory, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1), template, "openai-responses-1", "openai-responses-2"},
		"unknown inventory":     {bytes.Replace(inventory, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1), template, "openai-responses-1", "openai-responses-2"},
		"null inventory field":  {bytes.Replace(inventory, []byte(`"pricing_known":false`), []byte(`"pricing_known":null`), 1), template, "openai-responses-1", "openai-responses-2"},
		"trailing inventory":    {append(append([]byte(nil), inventory...), []byte(" {}")...), template, "openai-responses-1", "openai-responses-2"},
		"oversize inventory":    {bytes.Repeat([]byte{' '}, (8<<20)+1), template, "openai-responses-1", "openai-responses-2"},
		"nonlocal":              {bytes.Replace(inventory, []byte(`"zone":"local"`), []byte(`"zone":"private_remote"`), 1), template, "openai-responses-1", "openai-responses-2"},
		"ambiguous":             {bytes.Replace(inventory, []byte(`"adapter_id":"openai-responses-2"`), []byte(`"adapter_id":"openai-responses-1"`), 1), template, "openai-responses-1", "openai-responses-2"},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			inventoryPath := writeConfigIdentityProtectedFile(t, "routes.json", test.inventory, 0o600)
			templatePath := writeConfigIdentityProtectedFile(t, "template.json", test.template, 0o600)
			args := configBindArgs(inventoryPath, templatePath)
			args[6], args[8] = test.generation, test.verification
			var stdout, stderr bytes.Buffer
			if code := runConfig(args, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("invalid binding code=%d stdout bytes=%d stderr=%q", code, stdout.Len(), stderr.String())
			}
			assertInventoryIdentityNoLeak(t, stderr.String(), inventoryPath)
			assertInventoryIdentityNoLeak(t, stderr.String(), templatePath)
		})
	}
	if requests.Load() != 0 {
		t.Fatal("refused binding contacted a provider")
	}
}

func TestRunConfigBindRejectsArgumentsAndProtectedFilesWithoutEcho(t *testing.T) {
	inventoryPath := writeConfigIdentityProtectedFile(t, "routes.json", configIdentityInventoryDocument(t, "generation", "verification"), 0o600)
	templatePath := writeConfigIdentityProtectedFile(t, "template.json", configBindTemplate("http://127.0.0.1:11434/v1"), 0o600)
	valid := configBindArgs(inventoryPath, templatePath)
	duplicate := append([]string(nil), valid...)
	duplicate[7] = "--generation-adapter"
	unknown := append([]string(nil), valid...)
	unknown[7] = "--" + inventoryIdentityLeakSentinel
	empty := append([]string(nil), valid...)
	empty[8] = ""
	for _, args := range [][]string{{"bind"}, valid[:7], append(append([]string(nil), valid...), inventoryIdentityLeakSentinel), duplicate, unknown, empty} {
		var stdout, stderr bytes.Buffer
		if code := runConfig(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatalf("invalid arguments code=%d stdout bytes=%d", code, stdout.Len())
		}
		if strings.Contains(stderr.String(), inventoryIdentityLeakSentinel) || strings.Contains(stderr.String(), inventoryPath) || strings.Contains(stderr.String(), templatePath) {
			t.Fatal("usage error echoed input")
		}
	}
	for _, path := range []string{inventoryPath, templatePath} {
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		if code := runConfig(valid, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
			t.Fatal("unsafe input did not fail closed")
		}
		assertInventoryIdentityNoLeak(t, stderr.String(), path)
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	missing := append([]string(nil), valid...)
	missing[4] = filepath.Join(t.TempDir(), inventoryIdentityLeakSentinel)
	var stdout, stderr bytes.Buffer
	if code := runConfig(missing, &stdout, &stderr); code != 1 || stdout.Len() != 0 {
		t.Fatal("missing template did not fail closed")
	}
	assertInventoryIdentityNoLeak(t, stderr.String(), missing[4])
	for _, writer := range []io.Writer{shortNilWriter{}, leakingErrorWriter{}} {
		stderr.Reset()
		if code := runConfig(valid, writer, &stderr); code != 1 {
			t.Fatal("stdout writer failure was accepted")
		}
		assertInventoryIdentityNoLeak(t, stderr.String(), templatePath)
	}
}
