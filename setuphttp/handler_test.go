package setuphttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }
func request(t *testing.T, handler http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var content []byte
	if body != nil {
		content, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(content))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	return res
}
func setupHandlerFixture(t *testing.T) (http.Handler, string, string) {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "plan.json")
	token := "setup-" + strings.Repeat("s", 40)
	environment := func(name string) string {
		switch name {
		case "OPEN_TRESTLE_API_TOKEN":
			return "operator-" + strings.Repeat("a", 32)
		case "OPEN_TRESTLE_OBSERVER_TOKEN":
			return "observer-" + strings.Repeat("b", 32)
		}
		return ""
	}
	handler, err := New(Options{StatePath: state, Token: token, Environment: environment, Clock: fixedClock{time.UnixMilli(100).UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	return handler, state, token
}
func TestSetupHTTPInitializesInspectsAndRunsExactCheck(t *testing.T) {
	handler, state, token := setupHandlerFixture(t)
	res := request(t, handler, http.MethodGet, "/api/v1/setup", token, nil)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"initialized":false`) {
		t.Fatalf("get=%d %s", res.Code, res.Body.String())
	}
	for _, path := range []string{state, state + ".lock", state + ".receipts", state + ".next"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("created %s", path)
		}
	}
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "local_single_node", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	if res.Code != http.StatusCreated || !strings.Contains(res.Body.String(), `"initialized":true`) {
		t.Fatalf("init=%d %s", res.Code, res.Body.String())
	}
	var session struct {
		Plan json.RawMessage `json:"plan"`
	}
	if json.Unmarshal(res.Body.Bytes(), &session) != nil {
		t.Fatal("decode")
	}
	plan, err := setupcore.DecodePlan(session.Plan)
	if err != nil {
		t.Fatal(err)
	}
	check := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "observer_credential_posture_validated", "confirmation": "run observer_credential_posture_validated"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"state":"passed"`) {
		t.Fatalf("check=%d %s", res.Code, res.Body.String())
	}
	inspected, err := setupcore.InspectStateFile(context.Background(), state)
	if err != nil || inspected.Revision() != 2 || len(inspected.Receipts()) != 1 {
		t.Fatalf("plan=%d %v", inspected.Revision(), err)
	}
	for _, secret := range []string{"operator-", "observer-", token} {
		if strings.Contains(res.Body.String(), secret) {
			t.Fatalf("leaked %s", secret)
		}
	}
}
func TestSetupHTTPRejectsUnauthorizedStaleAndUnconfirmedRequests(t *testing.T) {
	handler, _, token := setupHandlerFixture(t)
	res := request(t, handler, http.MethodGet, "/api/v1/setup", "", nil)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("auth=%d", res.Code)
	}
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "local_single_node", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var session struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &session)
	plan, _ := setupcore.DecodePlan(session.Plan)
	for _, check := range []map[string]any{{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": strings.Repeat("a", 64), "key": "observer_credential_posture_validated", "confirmation": "run observer_credential_posture_validated"}, {"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "observer_credential_posture_validated", "confirmation": "run wrong"}} {
		res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
		if res.Code != http.StatusConflict && res.Code != http.StatusBadRequest {
			t.Fatalf("check=%d %s", res.Code, res.Body.String())
		}
	}
}
func TestSetupHTTPRejectsAmbiguousOrExcessiveJSON(t *testing.T) {
	handler, _, token := setupHandlerFixture(t)
	raw := `{"contract":"open-trestle/setup-init-request","contract":"open-trestle/setup-init-request","schema_version":1,"profile":"local_single_node","tenant_id":"tenant-a","repository_id":"repo-a","recovery_owner":"owner","confirmation":"create setup plan"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/init", strings.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("duplicate=%d", res.Code)
	}
	huge := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "local_single_node", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": strings.Repeat("a", 70000), "confirmation": "create setup plan"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/init", token, huge)
	if res.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("huge=%d", res.Code)
	}
	nested := strings.Repeat("[", 129) + "0" + strings.Repeat("]", 129)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/setup/init", strings.NewReader(nested))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("depth=%d", res.Code)
	}
}

func TestSetupHTTPRejectsSharedTokenAndRedactsFormatter(t *testing.T) {
	root := t.TempDir()
	token := "shared-" + strings.Repeat("a", 32)
	handler, err := New(Options{StatePath: filepath.Join(root, "plan.json"), Token: token, Environment: func(string) string { return token }, Clock: fixedClock{time.UnixMilli(1).UTC()}})
	if err == nil || handler != nil {
		t.Fatal("shared token accepted")
	}
	handler, err = New(Options{StatePath: filepath.Join(root, "plan.json"), Token: token, Environment: func(string) string { return "" }, Clock: fixedClock{time.UnixMilli(1).UTC()}})
	if err != nil || strings.Contains(fmt.Sprintf("%#v", handler), token) || fmt.Sprint(handler) != "setup HTTP handler" {
		t.Fatal("handler formatter leaked")
	}
}
func TestSetupHTTPRejectsMethodQueryAndBodyOnSession(t *testing.T) {
	handler, _, token := setupHandlerFixture(t)
	for _, test := range []struct {
		method, path string
		body         any
		want         int
	}{{http.MethodPost, "/api/v1/setup", map[string]any{}, http.StatusMethodNotAllowed}, {http.MethodGet, "/api/v1/setup?x=1", nil, http.StatusBadRequest}, {http.MethodGet, "/api/v1/setup", "body", http.StatusBadRequest}, {http.MethodGet, "/other", nil, http.StatusNotFound}} {
		res := request(t, handler, test.method, test.path, token, test.body)
		if res.Code != test.want {
			t.Fatalf("%s %s=%d", test.method, test.path, res.Code)
		}
	}
}
func TestSetupHTTPStorageCheckUsesExpectedPlanAndConfirmation(t *testing.T) {
	handler, state, token := setupHandlerFixture(t)
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "local_single_node", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res := request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var session struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &session)
	plan, _ := setupcore.DecodePlan(session.Plan)
	root := filepath.Dir(state)
	_ = os.Chmod(root, 0o700)
	check := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "state_storage_posture_validated", "confirmation": "run state_storage_posture_validated", "storage_root": root}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"state":"passed"`) {
		t.Fatalf("storage=%d %s", res.Code, res.Body.String())
	}
}

func setupHTTPPolicyFixture(t *testing.T, root string) (string, string, string, string, string) {
	return setupHTTPPolicyFixtureForZone(t, root, "local")
}
func setupHTTPPolicyFixtureForZone(t *testing.T, root, zone string) (string, string, string, string, string) {
	t.Helper()
	routes := make([]map[string]any, 2)
	connections := make([]map[string]any, 2)
	for index := range 2 {
		suffix := string(rune('a' + index))
		endpoint := "http://127.0.0.1:11434/v1"
		if index == 1 {
			endpoint = "http://[::1]:11435/v1"
		}
		if zone != "local" {
			endpoint = []string{"https://one.example/v1", "https://two.example/v1"}[index]
		}
		routes[index] = map[string]any{"zone": zone, "provider_id": "provider-" + suffix, "adapter_id": "adapter-" + suffix, "connection_id": "connection-" + suffix, "model_id": "model-" + suffix, "model_version": "v1", "max_context_tokens": 64000, "max_output_tokens": 8192, "features": []string{"structured_output"}, "content_logging": "disabled", "pricing_known": true, "input_micro_usd_per_million_tokens": 0, "output_micro_usd_per_million_tokens": 0, "quality": "tier_3", "registry_revision": 1, "registry_status": "approved", "evidence_manifest_base64": base64.StdEncoding.EncodeToString([]byte(`{"approved":true}`)), "operational_revision": 1, "health": "healthy", "quota": "available", "performance_revision": 1, "latency_known": false, "p95_latency_milliseconds": 0, "latency_sample_count": 0}
		connections[index] = map[string]any{"implementation": "openai_responses", "adapter_id": "adapter-" + suffix, "endpoint": endpoint, "credential_environment": "OPEN_TRESTLE_PROVIDER_LOCAL_" + strings.ToUpper(suffix)}
	}
	inventoryBytes, _ := json.Marshal(map[string]any{"schema_version": 1, "routes": routes})
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryBytes))
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, _ := json.Marshal(map[string]any{"schema_version": 1, "inventory_identity": inventory.Identity(), "review_policy_identity": strings.Repeat("a", 64), "min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{zone}, "content_logging_allowed": false, "estimated_input_tokens": 1000, "max_output_tokens": 4096, "max_cost_micro_usd": 0, "pinned_route_record_identity": "", "preferred_route_record_identities": []string{}, "verification_independence": "distinct_provider", "publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true, "connections": connections})
	policy, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyBytes), inventory)
	if err != nil {
		t.Fatal(err)
	}
	inventoryPath, policyPath := filepath.Join(root, "routes.json"), filepath.Join(root, "policy.json")
	if os.WriteFile(inventoryPath, inventoryBytes, 0o600) != nil || os.WriteFile(policyPath, policyBytes, 0o600) != nil {
		t.Fatal("write")
	}
	return inventoryPath, policyPath, inventory.Identity(), policy.Identity(), policy.ReviewPolicyIdentity()
}
func TestSetupHTTPRunsApprovedPolicyAndNonPublishingDryRun(t *testing.T) {
	handler, state, token := setupHandlerFixture(t)
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "local_single_node", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res := request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var session struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &session)
	plan, _ := setupcore.DecodePlan(session.Plan)
	inventoryPath, policyPath, inventoryID, runtimeID, reviewID := setupHTTPPolicyFixture(t, filepath.Dir(state))
	base := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "policy_validated", "confirmation": "run policy_validated", "route_inventory_path": inventoryPath, "runtime_policy_path": policyPath, "approve_inventory_identity": inventoryID, "approve_runtime_policy_identity": runtimeID, "approve_review_policy_identity": reviewID, "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, base)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"state":"passed"`) {
		t.Fatalf("policy=%d %s", res.Code, res.Body.String())
	}
	var result struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &result)
	plan, _ = setupcore.DecodePlan(result.Plan)
	base["plan_identity"] = plan.Identity()
	base["key"] = "dry_run_validated"
	base["confirmation"] = "run dry_run_validated"
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, base)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"state":"passed"`) {
		t.Fatalf("dry=%d %s", res.Code, res.Body.String())
	}
	_ = json.Unmarshal(res.Body.Bytes(), &result)
	plan, _ = setupcore.DecodePlan(result.Plan)
	base["plan_identity"] = plan.Identity()
	base["key"] = "local_inference_validated"
	base["confirmation"] = "run local_inference_validated"
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, base)
	if res.Code != http.StatusUnprocessableEntity || !strings.Contains(res.Body.String(), `"code":"check_unavailable"`) {
		t.Fatalf("inference=%d %s", res.Code, res.Body.String())
	}
	for _, forbidden := range []string{"127.0.0.1", "OPEN_TRESTLE_PROVIDER", "candidate_generation", "verdicts"} {
		if strings.Contains(res.Body.String(), forbidden) {
			t.Fatalf("leaked %s", forbidden)
		}
	}
}

func TestSetupHTTPRejectsTypedNilClock(t *testing.T) {
	var clock *fixedClock
	handler, err := New(Options{StatePath: filepath.Join(t.TempDir(), "plan.json"), Token: "setup-" + strings.Repeat("s", 40), Environment: func(string) string { return "" }, Clock: clock})
	if err == nil || handler != nil {
		t.Fatal("typed nil clock accepted")
	}
}

func TestSetupHTTPOfflineBackupAndAdministratorChecks(t *testing.T) {
	handler, state, token := setupHandlerFixture(t)
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "local_single_node", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res := request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var session struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &session)
	plan, _ := setupcore.DecodePlan(session.Plan)
	backupRoot := t.TempDir()
	_ = os.Chmod(backupRoot, 0o700)
	snapshot := filepath.Join(backupRoot, "plan.snapshot.json")
	if _, err := setupcore.CreateBackupSnapshot(context.Background(), state, snapshot, plan.Identity()); err != nil {
		t.Fatal(err)
	}
	check := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "backup_validated", "confirmation": "run backup_validated", "backup_snapshot_path": snapshot}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"key":"backup_validated"`) || strings.Contains(res.Body.String(), snapshot) {
		t.Fatalf("backup=%d %s", res.Code, res.Body.String())
	}
	var result struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &result)
	plan, _ = setupcore.DecodePlan(result.Plan)
	check = map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "local_administrator_validated", "confirmation": "run local_administrator_validated", "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"key":"local_administrator_validated"`) || !strings.Contains(res.Body.String(), `"state":"passed"`) {
		t.Fatalf("administrator=%d %s", res.Code, res.Body.String())
	}
	check["backup_snapshot_path"] = snapshot
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("crossed=%d %s", res.Code, res.Body.String())
	}
}

type setupHTTPInferenceFactory struct{}

func (setupHTTPInferenceFactory) FactoryIdentity() string { return strings.Repeat("7", 64) }
func (setupHTTPInferenceFactory) Build(_ context.Context, inventory runtimeconfig.RouteInventory, _ runtimeconfig.RuntimePolicy) (gateway.RouteDispatcherCatalog, error) {
	dispatchers := make([]gateway.RouteDispatcher, 0)
	seen := map[string]bool{}
	for _, candidate := range inventory.Candidates() {
		route := candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		if !seen[route.AdapterID()] {
			seen[route.AdapterID()] = true
			dispatchers = append(dispatchers, setupHTTPInferenceDispatcher{route.AdapterID(), strings.Repeat(string(rune('1'+len(dispatchers))), 64)})
		}
	}
	return gateway.NewRouteDispatcherCatalog(dispatchers)
}

type setupHTTPInferenceDispatcher struct{ adapter, identity string }

func (d setupHTTPInferenceDispatcher) AdapterID() string             { return d.adapter }
func (d setupHTTPInferenceDispatcher) ConfigurationIdentity() string { return d.identity }
func (d setupHTTPInferenceDispatcher) DispatchRoute(_ context.Context, request gateway.RouteDispatchRequest) gateway.RouteDispatchResult {
	document := `{"schema_version":1,"verdicts":[]}`
	if strings.Contains(string(request.Request().Payload()), "candidate_generation") {
		document = `{"schema_version":1,"candidates":[]}`
	}
	part, _ := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
	usage, _ := provider.NewRouteTokenUsage(1, 1, 0)
	response, _ := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	result, _ := gateway.NewSuccessfulRouteDispatchResult(response)
	return result
}
func TestSetupHTTPRunsExplicitLocalInferenceThroughInjectedFactory(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "plan.json")
	token := "setup-" + strings.Repeat("s", 40)
	handler, err := New(Options{StatePath: state, Token: token, Environment: func(string) string { return "" }, LocalInferenceFactory: setupHTTPInferenceFactory{}, Clock: fixedClock{time.UnixMilli(100).UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "local_single_node", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res := request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var session struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &session)
	plan, _ := setupcore.DecodePlan(session.Plan)
	inventoryPath, policyPath, inventoryID, runtimeID, reviewID := setupHTTPPolicyFixture(t, root)
	check := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "policy_validated", "confirmation": "run policy_validated", "route_inventory_path": inventoryPath, "runtime_policy_path": policyPath, "approve_inventory_identity": inventoryID, "approve_runtime_policy_identity": runtimeID, "approve_review_policy_identity": reviewID, "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	var result struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &result)
	plan, _ = setupcore.DecodePlan(result.Plan)
	check["plan_identity"] = plan.Identity()
	check["key"] = "local_inference_validated"
	check["confirmation"] = "run local_inference_validated"
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"key":"local_inference_validated"`) || !strings.Contains(res.Body.String(), `"state":"passed"`) {
		t.Fatalf("inference=%d %s", res.Code, res.Body.String())
	}
	for _, forbidden := range []string{"candidate_generation", "verdicts", "127.0.0.1", "OPEN_TRESTLE_PROVIDER", "model-a", "adapter-a"} {
		if strings.Contains(res.Body.String(), forbidden) {
			t.Fatalf("leaked %s", forbidden)
		}
	}
}

func TestSetupHTTPRejectsCaseFoldedRequestMembersBeforeStateAccess(t *testing.T) {
	initBodies := []string{
		`{"Contract":"open-trestle/setup-init-request","schema_version":1,"profile":"local_single_node","tenant_id":"tenant-a","repository_id":"repo-a","recovery_owner":"owner","confirmation":"create setup plan"}`,
		`{"contract":"open-trestle/setup-init-request","Contract":"open-trestle/setup-init-request","schema_version":1,"profile":"local_single_node","tenant_id":"tenant-a","repository_id":"repo-a","recovery_owner":"owner","confirmation":"create setup plan"}`,
	}
	checkBodies := []string{
		`{"contract":"open-trestle/setup-check-request","schema_version":1,"plan_identity":"` + strings.Repeat("a", 64) + `","Key":"observer_credential_posture_validated","confirmation":"run observer_credential_posture_validated"}`,
		`{"contract":"open-trestle/setup-check-request","schema_version":1,"plan_identity":"` + strings.Repeat("a", 64) + `","key":"observer_credential_posture_validated","Confirmation":"run observer_credential_posture_validated"}`,
	}
	for index, value := range append(initBodies, checkBodies...) {
		handler, state, token := setupHandlerFixture(t)
		path := "/api/v1/setup/init"
		if index >= len(initBodies) {
			path = "/api/v1/setup/check"
		}
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(value))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("case %d=%d %s", index, res.Code, res.Body.String())
		}
		for _, candidate := range []string{state, state + ".lock", state + ".receipts", state + ".next"} {
			if _, err := os.Lstat(candidate); !os.IsNotExist(err) {
				t.Fatalf("case %d created %s", index, candidate)
			}
		}
	}
}

func TestSetupHTTPRejectsInvalidUTF8BeforeDecoding(t *testing.T) {
	handler, state, token := setupHandlerFixture(t)
	body := []byte(`{"contract":"open-trestle/setup-check-request","schema_version":1,"plan_identity":"` + strings.Repeat("a", 64) + `","key":"state_storage_posture_validated","confirmation":"run state_storage_posture_validated","storage_root":"/tmp/`)
	body = append(body, 0xff)
	body = append(body, []byte(`"}`)...)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/check", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status=%d %s", res.Code, res.Body.String())
	}
	if _, err := os.Lstat(state); !os.IsNotExist(err) {
		t.Fatal("state created")
	}
}

func TestSetupHTTPRejectsForbiddenFieldsByPresenceEvenWhenEmpty(t *testing.T) {
	base := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": strings.Repeat("a", 64)}
	cases := []map[string]any{
		{"key": "observer_credential_posture_validated", "confirmation": "run observer_credential_posture_validated", "storage_root": ""},
		{"key": "observer_credential_posture_validated", "confirmation": "run observer_credential_posture_validated", "approve_postgres_authority_identity": ""},
		{"key": "state_storage_posture_validated", "confirmation": "run state_storage_posture_validated", "storage_root": "/private", "approved_by": ""},
		{"key": "policy_validated", "confirmation": "run policy_validated", "route_inventory_path": "/routes", "runtime_policy_path": "/policy", "approve_inventory_identity": strings.Repeat("1", 64), "approve_runtime_policy_identity": strings.Repeat("2", 64), "approve_review_policy_identity": strings.Repeat("3", 64), "approved_by": "owner", "backup_snapshot_path": ""},
		{"key": "local_inference_validated", "confirmation": "run local_inference_validated", "route_inventory_path": "/routes", "runtime_policy_path": "/policy", "approve_inventory_identity": strings.Repeat("1", 64), "approve_runtime_policy_identity": strings.Repeat("2", 64), "approve_review_policy_identity": strings.Repeat("3", 64), "approved_by": "owner", "backup_snapshot_path": ""},
		{"key": "remote_provider_authorized", "confirmation": "run remote_provider_authorized", "route_inventory_path": "/routes", "runtime_policy_path": "/policy", "approve_inventory_identity": strings.Repeat("1", 64), "approve_runtime_policy_identity": strings.Repeat("2", 64), "approve_review_policy_identity": strings.Repeat("3", 64), "approved_by": "owner", "backup_snapshot_path": ""},
		{"key": "postgres_storage_validated", "confirmation": "run postgres_storage_validated", "approve_postgres_authority_identity": strings.Repeat("1", 64), "approved_by": "owner", "backup_snapshot_path": ""},
		{"key": "observer_credential_posture_validated", "confirmation": "run observer_credential_posture_validated", "kms_region": ""},
		{"key": "secret_backend_validated", "confirmation": "run secret_backend_validated", "approve_kms_authority_identity": strings.Repeat("1", 64), "kms_region": "us-east-1", "kms_key_arn": "arn:example", "kms_endpoint": "", "approved_by": "owner"},
		{"key": "secret_backend_validated", "confirmation": "run secret_backend_validated", "approve_kms_authority_identity": strings.Repeat("1", 64), "kms_region": "us-east-1", "kms_key_arn": "arn:example", "approved_by": "owner", "approve_postgres_authority_identity": ""},
		{"key": "observer_credential_posture_validated", "confirmation": "run observer_credential_posture_validated", "s3_endpoint": ""},
		{"key": "secret_backend_validated", "confirmation": "run secret_backend_validated", "approve_kms_authority_identity": strings.Repeat("1", 64), "kms_region": "us-east-1", "kms_key_arn": "arn:example", "approved_by": "owner", "s3_bucket": ""},
		{"key": "envelope_storage_validated", "confirmation": "run envelope_storage_validated", "approve_envelope_storage_authority_identity": strings.Repeat("1", 64), "s3_endpoint": "https://s3.example", "s3_region": "us-east-1", "s3_bucket": "artifacts", "s3_prefix": "reviews", "kms_region": "us-east-1", "kms_key_arn": "arn:example", "kms_endpoint": "", "approved_by": "owner"},
		{"key": "envelope_storage_validated", "confirmation": "run envelope_storage_validated", "approve_envelope_storage_authority_identity": strings.Repeat("1", 64), "s3_endpoint": "https://s3.example", "s3_region": "us-east-1", "s3_bucket": "artifacts", "s3_prefix": "reviews", "kms_region": "us-east-1", "kms_key_arn": "arn:example", "approved_by": "owner", "approve_kms_authority_identity": ""},
		{"key": "observer_credential_posture_validated", "confirmation": "run observer_credential_posture_validated", "github_api_endpoint": ""},
		{"key": "integration_permissions_validated", "confirmation": "run integration_permissions_validated", "approve_integration_permission_authority_identity": strings.Repeat("1", 64), "github_api_endpoint": "https://api.github.com", "github_api_version": "2026-03-10", "github_installation_id": 42, "github_repository_full_name": "owner/repo", "approved_by": "owner", "route_inventory_path": ""},
		{"key": "integration_permissions_validated", "confirmation": "run integration_permissions_validated", "approve_integration_permission_authority_identity": strings.Repeat("1", 64), "github_api_endpoint": "https://api.github.com", "github_api_version": "2026-02-30", "github_installation_id": 42, "github_repository_full_name": "owner/repo", "approved_by": "owner"},
		{"key": "integration_permissions_validated", "confirmation": "run integration_permissions_validated", "approve_integration_permission_authority_identity": strings.Repeat("1", 64), "github_api_endpoint": "https://169.254.169.254", "github_api_version": "2026-03-10", "github_installation_id": 42, "github_repository_full_name": "owner/repo", "approved_by": "owner"},
		{"key": "integration_permissions_validated", "confirmation": "run integration_permissions_validated", "approve_integration_permission_authority_identity": strings.Repeat("1", 64), "github_api_endpoint": "https://api.github.com", "github_api_version": "2026-03-10", "github_installation_id": 9007199254740992, "github_repository_full_name": "Owner/Repo", "approved_by": "owner"},
		{"key": "integration_permissions_validated", "confirmation": "run integration_permissions_validated", "approve_integration_permission_authority_identity": strings.Repeat("1", 64), "github_api_endpoint": "https://api.github.com", "github_api_version": "2026-03-10", "github_installation_id": 42, "github_repository_full_name": "Owner/.github", "approved_by": "owner"},
		{"key": "webhook_validated", "confirmation": "run webhook_validated", "approve_webhook_authority_identity": strings.Repeat("1", 64), "github_webhook_key_id": "", "approved_by": "owner"},
		{"key": "webhook_validated", "confirmation": "run webhook_validated", "approve_webhook_authority_identity": strings.Repeat("1", 64), "github_webhook_key_id": " bad ", "approved_by": "owner"},
		{"key": "webhook_validated", "confirmation": "run webhook_validated", "approve_webhook_authority_identity": strings.Repeat("1", 64), "github_webhook_key_id": "primary", "approved_by": "owner", "github_api_endpoint": ""},
		{"key": "shared_rate_limit_validated", "confirmation": "run shared_rate_limit_validated", "approve_shared_rate_limit_authority_identity": strings.Repeat("1", 64), "postgres_database_authority_identity": "", "approved_by": "owner"},
		{"key": "shared_rate_limit_validated", "confirmation": "run shared_rate_limit_validated", "approve_shared_rate_limit_authority_identity": strings.Repeat("1", 64), "postgres_database_authority_identity": strings.Repeat("2", 64), "approved_by": "owner", "github_webhook_key_id": ""},
		{"key": "replica_reconciliation_validated", "confirmation": "run replica_reconciliation_validated", "approve_replica_reconciliation_authority_identity": strings.Repeat("1", 64), "postgres_database_authority_identity": "", "approved_by": "owner"},
		{"key": "replica_reconciliation_validated", "confirmation": "run replica_reconciliation_validated", "approve_replica_reconciliation_authority_identity": strings.Repeat("1", 64), "postgres_database_authority_identity": strings.Repeat("2", 64), "approved_by": "owner", "approve_shared_rate_limit_authority_identity": ""},
		{"key": "observer_credential_posture_validated", "confirmation": "run observer_credential_posture_validated", "approve_replica_reconciliation_authority_identity": ""},
		{"key": "signed_bundle_validated", "confirmation": "run signed_bundle_validated", "approve_signed_bundle_authority_identity": strings.Repeat("1", 64), "bundle_path": "/private/release.bundle", "bundle_sha256": strings.Repeat("2", 64), "bundle_bytes": 0, "public_key": strings.Repeat("3", 64), "signature": strings.Repeat("4", 128), "approved_by": "owner"},
		{"key": "signed_bundle_validated", "confirmation": "run signed_bundle_validated", "approve_signed_bundle_authority_identity": strings.Repeat("1", 64), "bundle_path": "/private/release.bundle", "bundle_sha256": strings.Repeat("A", 64), "bundle_bytes": 1024, "public_key": strings.Repeat("3", 64), "signature": strings.Repeat("4", 128), "approved_by": "owner"},
		{"key": "signed_bundle_validated", "confirmation": "run signed_bundle_validated", "approve_signed_bundle_authority_identity": strings.Repeat("1", 64), "bundle_path": "/private/release.bundle", "bundle_sha256": strings.Repeat("2", 64), "bundle_bytes": 1024, "public_key": strings.Repeat("3", 64), "signature": strings.Repeat("4", 128), "approved_by": "owner", "approve_shared_rate_limit_authority_identity": ""},
		{"key": "observer_credential_posture_validated", "confirmation": "run observer_credential_posture_validated", "bundle_path": ""},
	}
	for index, fields := range cases {
		handler, state, token := setupHandlerFixture(t)
		body := map[string]any{}
		for key, value := range base {
			body[key] = value
		}
		for key, value := range fields {
			body[key] = value
		}
		res := request(t, handler, http.MethodPost, "/api/v1/setup/check", token, body)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("case %d=%d %s", index, res.Code, res.Body.String())
		}
		for _, candidate := range []string{state, state + ".lock", state + ".receipts", state + ".next"} {
			if _, err := os.Lstat(candidate); !os.IsNotExist(err) {
				t.Fatalf("case %d created %s", index, candidate)
			}
		}
	}
}

func TestSetupHTTPRejectsNonUTF8JSONCharsetBeforeStateAccess(t *testing.T) {
	handler, state, token := setupHandlerFixture(t)
	body := `{"contract":"open-trestle/setup-check-request","schema_version":1,"plan_identity":"` + strings.Repeat("a", 64) + `","key":"observer_credential_posture_validated","confirmation":"run observer_credential_posture_validated"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/check", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json; charset=iso-8859-1")
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d %s", res.Code, res.Body.String())
	}
	if _, err := os.Lstat(state); !os.IsNotExist(err) {
		t.Fatal("state created")
	}
	handler, _, token = setupHandlerFixture(t)
	initBody := `{"contract":"open-trestle/setup-init-request","schema_version":1,"profile":"local_single_node","tenant_id":"tenant-a","repository_id":"repo-a","recovery_owner":"owner","confirmation":"create setup plan"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/setup/init", strings.NewReader(initBody))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("utf8=%d %s", res.Code, res.Body.String())
	}
}

type setupHTTPPostgresProbe struct {
	identity, authority string
	calls               int
}

func (p *setupHTTPPostgresProbe) ConfigurationIdentity() string { return p.identity }
func (p *setupHTTPPostgresProbe) Probe(context.Context) setupcore.PostgresStorageProbeResult {
	p.calls++
	return setupcore.NewVerifiedPostgresStorageProbeResult(p.authority)
}
func TestSetupHTTPRunsConfirmedPostgresStorageCheck(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "plan.json")
	token := "setup-" + strings.Repeat("s", 40)
	authority := strings.Repeat("a", 64)
	probe := &setupHTTPPostgresProbe{identity: strings.Repeat("b", 64), authority: authority}
	handler, err := New(Options{StatePath: state, Token: token, Environment: func(string) string { return "" }, PostgresProbe: probe, Clock: fixedClock{time.UnixMilli(100).UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "controlled_hybrid", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res := request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var session struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &session)
	plan, _ := setupcore.DecodePlan(session.Plan)
	check := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "postgres_storage_validated", "confirmation": "run postgres_storage_validated", "approve_postgres_authority_identity": authority, "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusOK || probe.calls != 1 || !strings.Contains(res.Body.String(), `"key":"postgres_storage_validated"`) || !strings.Contains(res.Body.String(), `"state":"passed"`) {
		t.Fatalf("result=%d calls=%d %s", res.Code, probe.calls, res.Body.String())
	}
}

type setupHTTPSecretProbe struct {
	identity, authority string
	calls               int
}

func (p *setupHTTPSecretProbe) ConfigurationIdentity() string { return p.identity }
func (p *setupHTTPSecretProbe) AuthorityIdentity() string     { return p.authority }
func (p *setupHTTPSecretProbe) Probe(context.Context) setupcore.SecretBackendProbeResult {
	p.calls++
	return setupcore.NewVerifiedSecretBackendProbeResult(p.authority)
}
func TestSetupHTTPRunsConfirmedSecretBackendCheck(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state.json")
	token := "setup-" + strings.Repeat("s", 40)
	authority := strings.Repeat("a", 64)
	probe := &setupHTTPSecretProbe{identity: strings.Repeat("b", 64), authority: authority}
	builderCalls := 0
	handler, err := New(Options{StatePath: state, Token: token, Environment: func(string) string { return "" }, SecretBackendProbeBuilder: func(tenant, region, keyARN, endpoint string) (setupcore.SecretBackendProbe, error) {
		builderCalls++
		if tenant != "tenant-a" || region != "us-east-1" || keyARN != "arn:example:kms-key" || endpoint != "https://kms.example" {
			t.Fatal("crossed secret configuration")
		}
		return probe, nil
	}, Clock: fixedClock{time.UnixMilli(100).UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "controlled_hybrid", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res := request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var session struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &session)
	plan, _ := setupcore.DecodePlan(session.Plan)
	check := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "secret_backend_validated", "confirmation": "run secret_backend_validated", "approve_kms_authority_identity": authority, "kms_region": "us-east-1", "kms_key_arn": "arn:example:kms-key", "kms_endpoint": "https://kms.example", "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusOK || builderCalls != 1 || probe.calls != 1 || !strings.Contains(res.Body.String(), `"key":"secret_backend_validated"`) || !strings.Contains(res.Body.String(), `"state":"passed"`) {
		t.Fatalf("result=(%d,%q,%d,%d)", res.Code, res.Body.String(), builderCalls, probe.calls)
	}
	check["plan_identity"] = strings.Repeat("f", 64)
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusConflict || builderCalls != 1 || probe.calls != 1 {
		t.Fatalf("stale=(%d,%d,%d)", res.Code, builderCalls, probe.calls)
	}
}

type setupHTTPEnvelopeProbe struct {
	identity, authority, conformance string
	calls                            int
}

func (p *setupHTTPEnvelopeProbe) ConfigurationIdentity() string { return p.identity }
func (p *setupHTTPEnvelopeProbe) AuthorityIdentity() string     { return p.authority }
func (p *setupHTTPEnvelopeProbe) Probe(context.Context) setupcore.EnvelopeStorageProbeResult {
	p.calls++
	return setupcore.NewVerifiedEnvelopeStorageProbeResult(p.authority, p.conformance)
}
func TestSetupHTTPRunsConfirmedEnvelopeStorageCheck(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state.json")
	token := "setup-" + strings.Repeat("s", 40)
	authority := strings.Repeat("a", 64)
	probe := &setupHTTPEnvelopeProbe{strings.Repeat("b", 64), authority, strings.Repeat("c", 64), 0}
	builderCalls := 0
	handler, err := New(Options{StatePath: state, Token: token, Environment: func(string) string { return "" }, EnvelopeStorageProbeBuilder: func(plan setupcore.Plan, s3Endpoint, s3Region, s3Bucket, s3Prefix, kmsRegion, kmsKeyARN, kmsEndpoint string) (setupcore.EnvelopeStorageProbe, error) {
		builderCalls++
		if plan.TenantID() != "tenant-a" || s3Endpoint != "https://s3.example" || s3Region != "us-east-1" || s3Bucket != "artifacts" || s3Prefix != "reviews" || kmsRegion != "us-east-1" || kmsKeyARN != "arn:example:kms" || kmsEndpoint != "https://kms.example" {
			t.Fatal("crossed envelope configuration")
		}
		return probe, nil
	}, Clock: fixedClock{time.UnixMilli(100).UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "controlled_hybrid", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res := request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var session struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &session)
	plan, _ := setupcore.DecodePlan(session.Plan)
	check := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "envelope_storage_validated", "confirmation": "run envelope_storage_validated", "approve_envelope_storage_authority_identity": authority, "s3_endpoint": "https://s3.example", "s3_region": "us-east-1", "s3_bucket": "artifacts", "s3_prefix": "reviews", "kms_region": "us-east-1", "kms_key_arn": "arn:example:kms", "kms_endpoint": "https://kms.example", "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusOK || builderCalls != 1 || probe.calls != 1 || !strings.Contains(res.Body.String(), `"key":"envelope_storage_validated"`) || !strings.Contains(res.Body.String(), `"state":"passed"`) {
		t.Fatalf("result=(%d,%q,%d,%d)", res.Code, res.Body.String(), builderCalls, probe.calls)
	}
	check["plan_identity"] = strings.Repeat("f", 64)
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusConflict || builderCalls != 1 || probe.calls != 1 {
		t.Fatalf("stale=(%d,%d,%d)", res.Code, builderCalls, probe.calls)
	}
}

func TestSetupHTTPRunsRemoteProviderAuthorizationWithoutCredentials(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state.json")
	token := "setup-" + strings.Repeat("s", 40)
	handler, err := New(Options{StatePath: state, Token: token, Environment: func(name string) string {
		if strings.HasPrefix(name, "OPEN_TRESTLE_PROVIDER_") {
			t.Fatal("provider credential read")
		}
		return ""
	}, Clock: fixedClock{time.UnixMilli(100).UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "controlled_hybrid", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res := request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var session struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &session)
	plan, _ := setupcore.DecodePlan(session.Plan)
	inventoryPath, policyPath, inventoryID, runtimeID, reviewID := setupHTTPPolicyFixtureForZone(t, root, "private_remote")
	check := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "remote_provider_authorized", "confirmation": "run remote_provider_authorized", "route_inventory_path": inventoryPath, "runtime_policy_path": policyPath, "approve_inventory_identity": inventoryID, "approve_runtime_policy_identity": runtimeID, "approve_review_policy_identity": reviewID, "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"key":"remote_provider_authorized"`) || !strings.Contains(res.Body.String(), `"state":"passed"`) {
		t.Fatalf("result=%d %s", res.Code, res.Body.String())
	}
}

type setupHTTPIntegrationPermissionProbe struct {
	identity, authority, observation string
	calls                            int
}

func (p *setupHTTPIntegrationPermissionProbe) ConfigurationIdentity() string { return p.identity }
func (p *setupHTTPIntegrationPermissionProbe) AuthorityIdentity() string     { return p.authority }
func (p *setupHTTPIntegrationPermissionProbe) Probe(context.Context) setupcore.IntegrationPermissionProbeResult {
	p.calls++
	return setupcore.NewVerifiedIntegrationPermissionProbeResult(p.authority, p.observation)
}
func TestSetupHTTPRunsConfirmedIntegrationPermissionCheck(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state.json")
	token := "setup-" + strings.Repeat("s", 40)
	authority := strings.Repeat("a", 64)
	probe := &setupHTTPIntegrationPermissionProbe{strings.Repeat("b", 64), authority, strings.Repeat("c", 64), 0}
	builderCalls := 0
	handler, err := New(Options{StatePath: state, Token: token, Environment: func(string) string { return "" }, IntegrationPermissionProbeBuilder: func(plan setupcore.Plan, common string, allow bool) (setupcore.IntegrationPermissionProbe, error) {
		builderCalls++
		if plan.TenantID() != "tenant-a" || plan.RepositoryID() != "repo-a" || common != strings.Repeat("d", 64) || !allow {
			t.Fatal("crossed integration configuration")
		}
		return probe, nil
	}, Clock: fixedClock{time.UnixMilli(100).UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "controlled_hybrid", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res := request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var session struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &session)
	plan, _ := setupcore.DecodePlan(session.Plan)
	check := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 2, "plan_identity": plan.Identity(), "key": "integration_permissions_validated", "confirmation": "create GitHub installation token and run integration_permissions_validated", "approve_integration_permission_authority_identity": authority, "approve_github_source_broker_authority_identity": strings.Repeat("d", 64), "allow_github_installation_token_creation": true, "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusOK || builderCalls != 1 || probe.calls != 1 || !strings.Contains(res.Body.String(), `"key":"integration_permissions_validated"`) {
		t.Fatalf("result=%d %s calls=%d/%d", res.Code, res.Body.String(), builderCalls, probe.calls)
	}
	check["plan_identity"] = strings.Repeat("f", 64)
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusConflict || builderCalls != 1 || probe.calls != 1 {
		t.Fatalf("stale=%d calls=%d/%d", res.Code, builderCalls, probe.calls)
	}
}

type setupHTTPWebhookProbe struct {
	identity, authority, observation string
	calls                            int
}

func (p *setupHTTPWebhookProbe) ConfigurationIdentity() string { return p.identity }
func (p *setupHTTPWebhookProbe) AuthorityIdentity() string     { return p.authority }
func (p *setupHTTPWebhookProbe) Probe(context.Context) setupcore.WebhookProbeResult {
	p.calls++
	return setupcore.NewVerifiedWebhookProbeResult(p.authority, p.observation)
}

func TestSetupHTTPRunsWebhookOnlyAfterPermissionAndFreshPlan(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state.json")
	token := "setup-" + strings.Repeat("s", 40)
	permissionAuthority, webhookAuthority := strings.Repeat("a", 64), strings.Repeat("d", 64)
	permissionProbe := &setupHTTPIntegrationPermissionProbe{strings.Repeat("b", 64), permissionAuthority, strings.Repeat("c", 64), 0}
	webhookProbe := &setupHTTPWebhookProbe{strings.Repeat("e", 64), webhookAuthority, strings.Repeat("f", 64), 0}
	webhookBuilderCalls := 0
	handler, err := New(Options{StatePath: state, Token: token, Environment: func(string) string { return "" }, IntegrationPermissionProbeBuilder: func(plan setupcore.Plan, common string, allow bool) (setupcore.IntegrationPermissionProbe, error) {
		if plan.TenantID() != "tenant-a" || plan.RepositoryID() != "repo-a" || common != strings.Repeat("1", 64) || !allow {
			t.Fatal("crossed integration configuration")
		}
		return permissionProbe, nil
	}, WebhookProbeBuilder: func(plan setupcore.Plan, keyID string) (setupcore.WebhookProbe, error) {
		webhookBuilderCalls++
		if plan.TenantID() != "tenant-a" || plan.RepositoryID() != "repo-a" || keyID != "primary-2026" {
			t.Fatal("crossed webhook configuration")
		}
		return webhookProbe, nil
	}, Clock: fixedClock{time.UnixMilli(100).UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "controlled_hybrid", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res := request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var initial struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &initial)
	plan, _ := setupcore.DecodePlan(initial.Plan)
	permissionCheck := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 2, "plan_identity": plan.Identity(), "key": "integration_permissions_validated", "confirmation": "create GitHub installation token and run integration_permissions_validated", "approve_integration_permission_authority_identity": permissionAuthority, "approve_github_source_broker_authority_identity": strings.Repeat("1", 64), "allow_github_installation_token_creation": true, "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, permissionCheck)
	if res.Code != http.StatusOK {
		t.Fatalf("permission=%d %s", res.Code, res.Body.String())
	}
	var permissionResult struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &permissionResult)
	next, _ := setupcore.DecodePlan(permissionResult.Plan)
	webhookCheck := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "webhook_validated", "confirmation": "run webhook_validated", "approve_webhook_authority_identity": webhookAuthority, "github_webhook_key_id": "primary-2026", "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, webhookCheck)
	if res.Code != http.StatusConflict || webhookBuilderCalls != 0 || webhookProbe.calls != 0 {
		t.Fatalf("stale=%d calls=%d/%d", res.Code, webhookBuilderCalls, webhookProbe.calls)
	}
	webhookCheck["plan_identity"] = next.Identity()
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, webhookCheck)
	if res.Code != http.StatusOK || webhookBuilderCalls != 1 || webhookProbe.calls != 1 || !strings.Contains(res.Body.String(), `"key":"webhook_validated"`) || !strings.Contains(res.Body.String(), `"state":"passed"`) {
		t.Fatalf("result=%d %s calls=%d/%d", res.Code, res.Body.String(), webhookBuilderCalls, webhookProbe.calls)
	}
}

type setupHTTPSharedRateLimitProbe struct {
	identity, authority, observation string
	calls                            int
}

func (p *setupHTTPSharedRateLimitProbe) ConfigurationIdentity() string { return p.identity }
func (p *setupHTTPSharedRateLimitProbe) AuthorityIdentity() string     { return p.authority }
func (p *setupHTTPSharedRateLimitProbe) Probe(context.Context) setupcore.SharedRateLimitProbeResult {
	p.calls++
	return setupcore.NewVerifiedSharedRateLimitProbeResult(p.authority, p.observation)
}
func TestSetupHTTPRunsSharedRateLimitAfterPostgresAndFreshPlan(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state.json")
	token := "setup-" + strings.Repeat("s", 40)
	databaseAuthority := strings.Repeat("a", 64)
	postgresProbe := &setupHTTPPostgresProbe{strings.Repeat("b", 64), databaseAuthority, 0}
	rateAuthority := strings.Repeat("c", 64)
	rateProbe := &setupHTTPSharedRateLimitProbe{strings.Repeat("d", 64), rateAuthority, strings.Repeat("e", 64), 0}
	builderCalls := 0
	handler, err := New(Options{StatePath: state, Token: token, Environment: func(string) string { return "" }, PostgresProbe: postgresProbe, SharedRateLimitProbeBuilder: func(plan setupcore.Plan, database string) (setupcore.SharedRateLimitProbe, error) {
		builderCalls++
		if plan.Profile() != setupcore.ProfileKubernetesHA || database != databaseAuthority {
			t.Fatal("crossed rate-limit configuration")
		}
		return rateProbe, nil
	}, Clock: fixedClock{time.UnixMilli(100).UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "kubernetes_ha", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res := request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var initial struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &initial)
	plan, _ := setupcore.DecodePlan(initial.Plan)
	postgresCheck := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "postgres_storage_validated", "confirmation": "run postgres_storage_validated", "approve_postgres_authority_identity": databaseAuthority, "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, postgresCheck)
	if res.Code != http.StatusOK {
		t.Fatalf("postgres=%d %s", res.Code, res.Body.String())
	}
	var post struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &post)
	next, _ := setupcore.DecodePlan(post.Plan)
	check := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "shared_rate_limit_validated", "confirmation": "run shared_rate_limit_validated", "approve_shared_rate_limit_authority_identity": rateAuthority, "postgres_database_authority_identity": databaseAuthority, "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusConflict || builderCalls != 0 || rateProbe.calls != 0 {
		t.Fatalf("stale=%d calls=%d/%d", res.Code, builderCalls, rateProbe.calls)
	}
	check["plan_identity"] = next.Identity()
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusOK || builderCalls != 1 || rateProbe.calls != 1 || !strings.Contains(res.Body.String(), `"key":"shared_rate_limit_validated"`) {
		t.Fatalf("result=%d %s calls=%d/%d", res.Code, res.Body.String(), builderCalls, rateProbe.calls)
	}
}

type setupHTTPReplicaReconciliationProbe struct {
	identity, authority, observation string
	calls                            int
}

func (p *setupHTTPReplicaReconciliationProbe) ConfigurationIdentity() string { return p.identity }
func (p *setupHTTPReplicaReconciliationProbe) AuthorityIdentity() string     { return p.authority }
func (p *setupHTTPReplicaReconciliationProbe) Probe(context.Context) setupcore.ReplicaReconciliationProbeResult {
	p.calls++
	return setupcore.NewVerifiedReplicaReconciliationProbeResult(p.authority, p.observation)
}

func TestSetupHTTPRunsReplicaReconciliationAfterPostgresAndFreshPlan(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state.json")
	token := "setup-" + strings.Repeat("s", 40)
	databaseAuthority := strings.Repeat("a", 64)
	postgresProbe := &setupHTTPPostgresProbe{strings.Repeat("b", 64), databaseAuthority, 0}
	reconciliationAuthority := strings.Repeat("c", 64)
	reconciliationProbe := &setupHTTPReplicaReconciliationProbe{strings.Repeat("d", 64), reconciliationAuthority, strings.Repeat("e", 64), 0}
	builderCalls := 0
	handler, err := New(Options{StatePath: state, Token: token, Environment: func(string) string { return "" }, PostgresProbe: postgresProbe, ReplicaReconciliationProbeBuilder: func(plan setupcore.Plan, database string) (setupcore.ReplicaReconciliationProbe, error) {
		builderCalls++
		if plan.Profile() != setupcore.ProfileKubernetesHA || database != databaseAuthority {
			t.Fatal("crossed reconciliation configuration")
		}
		return reconciliationProbe, nil
	}, Clock: fixedClock{time.UnixMilli(100).UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "kubernetes_ha", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res := request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var initial struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &initial)
	plan, _ := setupcore.DecodePlan(initial.Plan)
	postgresCheck := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "postgres_storage_validated", "confirmation": "run postgres_storage_validated", "approve_postgres_authority_identity": databaseAuthority, "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, postgresCheck)
	if res.Code != http.StatusOK {
		t.Fatalf("postgres=%d %s", res.Code, res.Body.String())
	}
	var post struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &post)
	next, _ := setupcore.DecodePlan(post.Plan)
	check := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": plan.Identity(), "key": "replica_reconciliation_validated", "confirmation": "run replica_reconciliation_validated", "approve_replica_reconciliation_authority_identity": reconciliationAuthority, "postgres_database_authority_identity": databaseAuthority, "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusConflict || builderCalls != 0 || reconciliationProbe.calls != 0 {
		t.Fatalf("stale=%d calls=%d/%d", res.Code, builderCalls, reconciliationProbe.calls)
	}
	check["plan_identity"] = next.Identity()
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusOK || builderCalls != 1 || reconciliationProbe.calls != 1 || !strings.Contains(res.Body.String(), `"key":"replica_reconciliation_validated"`) {
		t.Fatalf("result=%d %s calls=%d/%d", res.Code, res.Body.String(), builderCalls, reconciliationProbe.calls)
	}
}

type setupHTTPSignedBundleProbe struct {
	identity, authority, observation string
	calls                            int
}

func (p *setupHTTPSignedBundleProbe) ConfigurationIdentity() string { return p.identity }
func (p *setupHTTPSignedBundleProbe) AuthorityIdentity() string     { return p.authority }
func (p *setupHTTPSignedBundleProbe) Probe(context.Context) setupcore.SignedBundleProbeResult {
	p.calls++
	return setupcore.NewVerifiedSignedBundleProbeResult(p.authority, p.observation)
}

func TestSetupHTTPRunsSignedBundleOnlyForFreshPlan(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state.json")
	token := "setup-" + strings.Repeat("s", 40)
	bundlePath := filepath.Join(root, "release.bundle")
	bundleDigest := strings.Repeat("a", 64)
	publicKey := strings.Repeat("b", 64)
	signature := strings.Repeat("c", 128)
	authority := strings.Repeat("d", 64)
	probe := &setupHTTPSignedBundleProbe{strings.Repeat("e", 64), authority, strings.Repeat("f", 64), 0}
	builderCalls := 0
	handler, err := New(Options{StatePath: state, Token: token, Environment: func(string) string { return "" }, SignedBundleProbeBuilder: func(plan setupcore.Plan, path, digest string, bytes uint64, key, signatureValue string) (setupcore.SignedBundleProbe, error) {
		builderCalls++
		if plan.Profile() != setupcore.ProfileAirGapped || path != bundlePath || digest != bundleDigest || bytes != 1024 || key != publicKey || signatureValue != signature {
			t.Fatal("crossed signed bundle configuration")
		}
		return probe, nil
	}, Clock: fixedClock{time.UnixMilli(100).UTC()}})
	if err != nil {
		t.Fatal(err)
	}
	init := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "air_gapped", "tenant_id": "tenant-a", "repository_id": "repo-a", "recovery_owner": "owner", "confirmation": "create setup plan"}
	res := request(t, handler, http.MethodPost, "/api/v1/setup/init", token, init)
	var session struct {
		Plan json.RawMessage `json:"plan"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &session)
	plan, _ := setupcore.DecodePlan(session.Plan)
	check := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": strings.Repeat("1", 64), "key": "signed_bundle_validated", "confirmation": "run signed_bundle_validated", "approve_signed_bundle_authority_identity": authority, "bundle_path": bundlePath, "bundle_sha256": bundleDigest, "bundle_bytes": 1024, "public_key": publicKey, "signature": signature, "approved_by": "owner"}
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusConflict || builderCalls != 0 || probe.calls != 0 {
		t.Fatalf("stale=%d calls=%d/%d", res.Code, builderCalls, probe.calls)
	}
	check["plan_identity"] = plan.Identity()
	res = request(t, handler, http.MethodPost, "/api/v1/setup/check", token, check)
	if res.Code != http.StatusOK || builderCalls != 1 || probe.calls != 1 || !strings.Contains(res.Body.String(), `"key":"signed_bundle_validated"`) {
		t.Fatalf("result=%d %s calls=%d/%d", res.Code, res.Body.String(), builderCalls, probe.calls)
	}
	for _, forbidden := range []string{bundlePath, publicKey, signature} {
		if strings.Contains(res.Body.String(), forbidden) {
			t.Fatal("bundle input leaked")
		}
	}
}
