package setuphttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	setupcore "github.com/georgejieh/open-trestle/setup"
)

const setupBrokerHTTPConfirmation = "create GitHub installation token and run integration_permissions_validated"
const setupBrokerHTTPCurrentChecker = "8308da20feae56a9f00344d5ac0824bf5133f1eff42d2ab31bce83b172daf3e9"

type setupBrokerHTTPClock struct{}

func (setupBrokerHTTPClock) Now() time.Time { return time.UnixMilli(200).UTC() }

// This probe tests HTTP dispatch and Runner controls, not native issuance evidence.
type setupBrokerHTTPBoundary struct {
	handler                                    *Handler
	path, token, common, permission            string
	plan                                       setupcore.Plan
	builderCalls, probeCalls, environmentCalls int
	hostPresent                                bool
	tenant, repository                         string
	result                                     setupcore.IntegrationPermissionProbeResult
}

func (b *setupBrokerHTTPBoundary) ConfigurationIdentity() string { return strings.Repeat("c", 64) }
func (b *setupBrokerHTTPBoundary) AuthorityIdentity() string     { return b.permission }
func (b *setupBrokerHTTPBoundary) Probe(context.Context) setupcore.IntegrationPermissionProbeResult {
	b.probeCalls++
	return b.result
}
func (b *setupBrokerHTTPBoundary) build(plan setupcore.Plan, common string, allow bool) (setupcore.IntegrationPermissionProbe, error) {
	b.builderCalls++
	if plan.Identity() != b.plan.Identity() || !b.hostPresent || common != b.common || !allow || plan.TenantID() != b.tenant || plan.RepositoryID() != b.repository {
		return nil, errors.New("unavailable")
	}
	return b, nil
}
func newSetupBrokerHTTPBoundary(t *testing.T, stateMode string) *setupBrokerHTTPBoundary {
	t.Helper()
	b := &setupBrokerHTTPBoundary{
		path: filepath.Join(t.TempDir(), "plan.json"), token: "setup-" + strings.Repeat("s", 40),
		common: strings.Repeat("a", 64), permission: strings.Repeat("b", 64),
		hostPresent: true, tenant: "tenant-a", repository: "repo-a",
	}
	var err error
	if stateMode == "historic" {
		b.plan, err = setupcore.NewPlan(setupcore.ProfileControlledHybrid, b.tenant, b.repository, "owner", time.UnixMilli(100).UTC())
	} else {
		b.plan, err = setupcore.NewCurrentPlan(setupcore.ProfileControlledHybrid, b.tenant, b.repository, "owner", time.UnixMilli(100).UTC())
	}
	if err != nil {
		t.Fatal(err)
	}
	if stateMode != "absent" {
		state, openErr := setupcore.OpenStateFile(b.path)
		if openErr != nil {
			t.Fatal(openErr)
		}
		initErr := state.Initialize(context.Background(), b.plan)
		closeErr := state.Close()
		if initErr != nil || closeErr != nil {
			t.Fatalf("initialize=%v close=%v", initErr, closeErr)
		}
	}
	b.result = setupcore.NewVerifiedIntegrationPermissionProbeResult(b.permission, strings.Repeat("d", 64))
	b.handler, err = New(Options{
		StatePath: b.path, Token: b.token, Clock: setupBrokerHTTPClock{},
		Environment: func(name string) string {
			b.environmentCalls++
			switch name {
			case "OPEN_TRESTLE_API_TOKEN":
				return "operator-" + strings.Repeat("o", 40)
			case "OPEN_TRESTLE_OBSERVER_TOKEN":
				return "observer-" + strings.Repeat("v", 40)
			}
			return ""
		},
		IntegrationPermissionProbeBuilder: IntegrationPermissionProbeBuilder(b.build),
	})
	if err != nil {
		t.Fatal(err)
	}
	b.environmentCalls = 0
	return b
}
func (b *setupBrokerHTTPBoundary) wire(t *testing.T) string {
	t.Helper()
	encoded, err := json.Marshal(struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		PlanIdentity  string `json:"plan_identity"`
		Key           string `json:"key"`
		Confirmation  string `json:"confirmation"`
		Permission    string `json:"approve_integration_permission_authority_identity"`
		Common        string `json:"approve_github_source_broker_authority_identity"`
		Allow         bool   `json:"allow_github_installation_token_creation"`
		Actor         string `json:"approved_by"`
	}{"open-trestle/setup-check-request", 2, b.plan.Identity(), string(setupcore.CheckIntegrationPermissionsValidated), setupBrokerHTTPConfirmation, b.permission, b.common, true, "owner"})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
func setupBrokerHTTPObject(t *testing.T, raw string) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func setupBrokerHTTPEncode(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
func (b *setupBrokerHTTPBoundary) serve(raw, media string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/check", strings.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", media)
	res := httptest.NewRecorder()
	b.handler.ServeHTTP(res, req)
	return res
}
func setupBrokerHTTPError(t *testing.T, res *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var value struct {
		Contract string `json:"contract"`
		Version  int    `json:"schema_version"`
		Code     string `json:"code"`
	}
	decoder := json.NewDecoder(bytes.NewReader(res.Body.Bytes()))
	decoder.DisallowUnknownFields()
	if res.Code != status || decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || value.Contract != "open-trestle/setup-error" || value.Version != 1 || value.Code != code {
		t.Fatalf("response=%d %s; want %d %s", res.Code, res.Body.String(), status, code)
	}
	if res.Header().Get("Cache-Control") != "no-store" || res.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("unsafe headers")
	}
}
func (b *setupBrokerHTTPBoundary) noDispatch(t *testing.T) {
	t.Helper()
	if b.builderCalls != 0 || b.probeCalls != 0 || b.environmentCalls != 0 {
		t.Fatalf("builder=%d probe=%d environment=%d", b.builderCalls, b.probeCalls, b.environmentCalls)
	}
}
func (b *setupBrokerHTTPBoundary) noStateArtifacts(t *testing.T) {
	t.Helper()
	for _, suffix := range []string{"", ".lock", ".receipts", ".next"} {
		if _, err := os.Lstat(b.path + suffix); !os.IsNotExist(err) {
			t.Fatalf("unexpected state artifact %q: %v", suffix, err)
		}
	}
}
func (b *setupBrokerHTTPBoundary) unchanged(t *testing.T) {
	t.Helper()
	plan, err := setupcore.InspectStateFile(context.Background(), b.path)
	if err != nil || plan.Identity() != b.plan.Identity() || len(plan.Receipts()) != 0 {
		t.Fatalf("state changed: %v", err)
	}
}
func (b *setupBrokerHTTPBoundary) resultReceipt(t *testing.T, res *httptest.ResponseRecorder, expected setupcore.CheckState) {
	t.Helper()
	var value struct {
		Contract string          `json:"contract"`
		Version  int             `json:"schema_version"`
		Plan     json.RawMessage `json:"plan"`
		Receipt  json.RawMessage `json:"receipt"`
	}
	decoder := json.NewDecoder(bytes.NewReader(res.Body.Bytes()))
	decoder.DisallowUnknownFields()
	if res.Code != http.StatusOK || decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF || value.Contract != "open-trestle/setup-check-result" || value.Version != 1 {
		t.Fatalf("result=%d %s", res.Code, res.Body.String())
	}
	plan, planErr := setupcore.DecodePlan(value.Plan)
	receipt, receiptErr := setupcore.DecodeCheckReceipt(value.Receipt)
	if planErr != nil || receiptErr != nil {
		t.Fatalf("plan=%v receipt=%v", planErr, receiptErr)
	}
	if receipt.State() != expected || receipt.Key() != setupcore.CheckIntegrationPermissionsValidated || receipt.CheckerIdentity() != setupBrokerHTTPCurrentChecker || receipt.PlanIdentity() != b.plan.Identity() || plan.Revision() != b.plan.Revision()+1 || len(plan.Receipts()) != 1 || plan.Receipts()[0].Identity() != receipt.Identity() {
		t.Fatal("wrong receipt binding")
	}
	persisted, err := setupcore.InspectStateFile(context.Background(), b.path)
	if err != nil || persisted.Identity() != plan.Identity() {
		t.Fatalf("receipt not persisted: %v", err)
	}
	for _, forbidden := range []string{b.token, "operator-", "observer-", "PRIVATE KEY", "installation_token"} {
		if strings.Contains(res.Body.String(), forbidden) {
			t.Fatalf("response leaked %q", forbidden)
		}
	}
}

func TestSetupBrokerHTTPV2RunsThroughRunnerAndAcceptsKeyPermutation(t *testing.T) {
	for _, permutation := range []bool{false, true} {
		t.Run(map[bool]string{false: "encoder_order", true: "reverse_order"}[permutation], func(t *testing.T) {
			b := newSetupBrokerHTTPBoundary(t, "current")
			raw := b.wire(t)
			value := setupBrokerHTTPObject(t, raw)
			if len(value) != 9 {
				t.Fatal("fixture must contain exactly nine keys")
			}
			if permutation {
				keys := []string{"approved_by", "allow_github_installation_token_creation", "approve_github_source_broker_authority_identity", "approve_integration_permission_authority_identity", "confirmation", "key", "plan_identity", "schema_version", "contract"}
				parts := make([]string, 0, len(keys))
				for _, key := range keys {
					parts = append(parts, setupBrokerHTTPEncode(t, key)+":"+setupBrokerHTTPEncode(t, value[key]))
				}
				raw = "{" + strings.Join(parts, ",") + "}"
			}
			b.resultReceipt(t, b.serve(raw, "application/json; charset=utf-8"), setupcore.CheckPassed)
			if b.builderCalls != 1 || b.probeCalls != 1 || b.environmentCalls != 0 {
				t.Fatalf("builder=%d probe=%d environment=%d", b.builderCalls, b.probeCalls, b.environmentCalls)
			}
		})
	}
}

func TestSetupBrokerHTTPV2RejectsInvalidShapeBeforeMissingState(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"false_consent":      func(v map[string]any) { v["allow_github_installation_token_creation"] = false },
		"quoted_consent":     func(v map[string]any) { v["allow_github_installation_token_creation"] = "true" },
		"numeric_consent":    func(v map[string]any) { v["allow_github_installation_token_creation"] = 1 },
		"old_confirmation":   func(v map[string]any) { v["confirmation"] = "run integration_permissions_validated" },
		"wrong_confirmation": func(v map[string]any) { v["confirmation"] = setupBrokerHTTPConfirmation + " " },
		"wrong_contract":     func(v map[string]any) { v["contract"] = "open-trestle/setup-init-request" },
		"other_key_v2": func(v map[string]any) {
			v["key"] = "observer_credential_posture_validated"
			v["confirmation"] = "run observer_credential_posture_validated"
		},
		"version_string":   func(v map[string]any) { v["schema_version"] = "2" },
		"version_fraction": func(v map[string]any) { v["schema_version"] = 2.5 },
		"version_three":    func(v map[string]any) { v["schema_version"] = 3 },
		"actor_space":      func(v map[string]any) { v["approved_by"] = "two owners" },
		"actor_non_ascii":  func(v map[string]any) { v["approved_by"] = "own\u00e9r" },
		"actor_long":       func(v map[string]any) { v["approved_by"] = strings.Repeat("a", 129) },
	}
	keys := []string{"contract", "schema_version", "plan_identity", "key", "confirmation", "approve_integration_permission_authority_identity", "approve_github_source_broker_authority_identity", "allow_github_installation_token_creation", "approved_by"}
	for _, key := range keys {
		mutations["missing_"+key] = func(v map[string]any) { delete(v, key) }
		mutations["null_"+key] = func(v map[string]any) { v[key] = nil }
	}
	for _, key := range []string{"plan_identity", "approve_integration_permission_authority_identity", "approve_github_source_broker_authority_identity"} {
		for _, invalid := range []string{"", strings.Repeat("0", 64), strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("g", 64)} {
			mutations[key+"_invalid_"+invalid] = func(v map[string]any) { v[key] = invalid }
		}
	}
	for key, value := range map[string]any{
		"github_api_endpoint": "https://api.github.com", "github_api_version": "2022-11-28", "github_installation_id": 17, "github_repository_full_name": "owner/repository",
		"broker_config": "/private/config.json", "github_source_broker_config": "/private/config.json", "config": map[string]any{"app_id": 17},
		"private_key": "-----BEGIN PRIVATE KEY-----", "token": "synthetic-secret", "authorization_generation": strings.Repeat("e", 64),
		"storage_root": "/tmp/root", "approve_webhook_authority_identity": strings.Repeat("e", 64), "unknown": true,
	} {
		mutations["extra_"+key] = func(v map[string]any) { v[key] = value }
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			b := newSetupBrokerHTTPBoundary(t, "absent")
			value := setupBrokerHTTPObject(t, b.wire(t))
			mutate(value)
			setupBrokerHTTPError(t, b.serve(setupBrokerHTTPEncode(t, value), "application/json"), 400, "invalid_request")
			b.noDispatch(t)
			b.noStateArtifacts(t)
		})
	}
}

func TestSetupBrokerHTTPV2RejectsAmbiguousEncodingAndTransport(t *testing.T) {
	cases := []struct {
		name, media string
		status      int
		code        string
		mutate      func(string) string
	}{
		{"duplicate", "application/json", 400, "invalid_request", func(s string) string {
			return strings.TrimSuffix(s, "}") + `,"allow_github_installation_token_creation":true}`
		}},
		{"escaped_duplicate", "application/json", 400, "invalid_request", func(s string) string {
			return strings.TrimSuffix(s, "}") + `,"allow_github_installation_token_creatio\u006e":true}`
		}},
		{"casefolded_extra", "application/json", 400, "invalid_request", func(s string) string {
			return strings.TrimSuffix(s, "}") + `,"Allow_github_installation_token_creation":true}`
		}},
		{"casefolded_replacement", "application/json", 400, "invalid_request", func(s string) string { return strings.Replace(s, `"approved_by"`, `"Approved_by"`, 1) }},
		{"trailing_object", "application/json", 400, "invalid_request", func(s string) string { return s + "{}" }},
		{"invalid_utf8", "application/json", 400, "invalid_request", func(s string) string { return strings.Replace(s, `"owner"`, "\"own"+string([]byte{0xff})+"er\"", 1) }},
		{"oversize", "application/json", 413, "request_too_large", func(s string) string { return s + strings.Repeat(" ", 64<<10) }},
		{"wrong_media", "text/plain", 415, "unsupported_media_type", func(s string) string { return s }},
		{"missing_media", "", 415, "unsupported_media_type", func(s string) string { return s }},
		{"wrong_charset", "application/json; charset=latin1", 415, "unsupported_media_type", func(s string) string { return s }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newSetupBrokerHTTPBoundary(t, "absent")
			setupBrokerHTTPError(t, b.serve(tc.mutate(b.wire(t)), tc.media), tc.status, tc.code)
			b.noDispatch(t)
			b.noStateArtifacts(t)
		})
	}
}

func TestSetupBrokerHTTPLegacyIntegrationRefusedBeforeMissingState(t *testing.T) {
	for _, mode := range []string{"well_formed", "missing_quartet", "new_false_consent", "new_null_consent", "new_empty_common"} {
		t.Run(mode, func(t *testing.T) {
			b := newSetupBrokerHTTPBoundary(t, "absent")
			value := setupBrokerHTTPObject(t, b.wire(t))
			value["schema_version"] = 1
			value["confirmation"] = "run integration_permissions_validated"
			delete(value, "allow_github_installation_token_creation")
			delete(value, "approve_github_source_broker_authority_identity")
			value["github_api_endpoint"] = "https://api.github.com"
			value["github_api_version"] = "2022-11-28"
			value["github_installation_id"] = 17
			value["github_repository_full_name"] = "owner/repository"
			status, code := 400, "invalid_request"
			switch mode {
			case "well_formed":
				status, code = 422, "check_unavailable"
			case "missing_quartet":
				delete(value, "github_repository_full_name")
			case "new_false_consent":
				value["allow_github_installation_token_creation"] = false
			case "new_null_consent":
				value["allow_github_installation_token_creation"] = nil
			case "new_empty_common":
				value["approve_github_source_broker_authority_identity"] = ""
			}
			setupBrokerHTTPError(t, b.serve(setupBrokerHTTPEncode(t, value), "application/json"), status, code)
			b.noDispatch(t)
			b.noStateArtifacts(t)
		})
	}
}

func TestSetupBrokerHTTPStateBuilderAndCoreRefusalsAreDistinct(t *testing.T) {
	for _, mode := range []string{"missing_state", "invalid_state", "stale_plan", "wrong_common", "absent_host", "nil_builder", "descriptor_tenant", "descriptor_repository", "historic_catalog", "wrong_actor", "wrong_permission"} {
		t.Run(mode, func(t *testing.T) {
			stateMode := "current"
			if mode == "missing_state" {
				stateMode = "absent"
			}
			if mode == "historic_catalog" {
				stateMode = "historic"
			}
			b := newSetupBrokerHTTPBoundary(t, stateMode)
			value := setupBrokerHTTPObject(t, b.wire(t))
			status, code, builds := 422, "check_unavailable", 1
			switch mode {
			case "missing_state":
				status, code, builds = 409, "state_conflict", 0
			case "invalid_state":
				if err := os.WriteFile(b.path, []byte("not-json"), 0o600); err != nil {
					t.Fatal(err)
				}
				status, code, builds = 409, "state_conflict", 0
			case "stale_plan":
				value["plan_identity"] = strings.Repeat("f", 64)
				status, code, builds = 409, "stale_plan", 0
			case "wrong_common":
				value["approve_github_source_broker_authority_identity"] = strings.Repeat("f", 64)
			case "absent_host":
				b.hostPresent = false
			case "nil_builder":
				b.handler.integrationPermissionProbeBuilder = nil
				builds = 0
			case "descriptor_tenant":
				b.tenant = "another-tenant"
			case "descriptor_repository":
				b.repository = "another-repository"
			case "historic_catalog":
				code = "check_failed"
			case "wrong_actor":
				value["approved_by"] = "another-owner"
			case "wrong_permission":
				value["approve_integration_permission_authority_identity"] = strings.Repeat("f", 64)
			}
			res := b.serve(setupBrokerHTTPEncode(t, value), "application/json")
			if mode == "wrong_actor" || mode == "wrong_permission" {
				b.resultReceipt(t, res, setupcore.CheckBlocked)
			} else {
				setupBrokerHTTPError(t, res, status, code)
				if stateMode == "absent" {
					b.noStateArtifacts(t)
				} else if mode == "invalid_state" {
					content, err := os.ReadFile(b.path)
					if err != nil || string(content) != "not-json" {
						t.Fatalf("invalid state changed: %v", err)
					}
				} else {
					b.unchanged(t)
				}
			}
			if b.builderCalls != builds || b.probeCalls != 0 || b.environmentCalls != 0 {
				t.Fatalf("builder=%d want=%d probe=%d environment=%d", b.builderCalls, builds, b.probeCalls, b.environmentCalls)
			}
		})
	}
}

func TestSetupBrokerHTTPProbeOutcomesKeepReceiptSchemaOne(t *testing.T) {
	for _, state := range []setupcore.CheckState{setupcore.CheckBlocked, setupcore.CheckUnavailable} {
		t.Run(string(state), func(t *testing.T) {
			b := newSetupBrokerHTTPBoundary(t, "current")
			b.result = setupcore.NewInvalidIntegrationPermissionProbeResult()
			if state == setupcore.CheckUnavailable {
				b.result = setupcore.NewUnavailableIntegrationPermissionProbeResult()
			}
			b.resultReceipt(t, b.serve(b.wire(t), "application/json"), state)
			if b.builderCalls != 1 || b.probeCalls != 1 {
				t.Fatalf("builder=%d probe=%d", b.builderCalls, b.probeCalls)
			}
		})
	}
}

type setupBrokerHTTPBody struct{ reads int }

func (b *setupBrokerHTTPBody) Read([]byte) (int, error) {
	b.reads++
	return 0, errors.New("must not decode")
}
func (*setupBrokerHTTPBody) Close() error { return nil }

func TestSetupBrokerHTTPAuthorizationAndRouteFencesPrecedeBody(t *testing.T) {
	cases := []struct {
		name, method, path, auth string
		status                   int
		code                     string
	}{
		{"missing_auth", "POST", "/api/v1/setup/check", "", 401, "unauthorized"},
		{"wrong_auth", "POST", "/api/v1/setup/check", "Bearer wrong", 401, "unauthorized"},
		{"wrong_method", "GET", "/api/v1/setup/check", "valid", 405, "method_not_allowed"},
		{"wrong_path", "POST", "/api/v1/setup/unknown", "valid", 404, "not_found"},
		{"query", "POST", "/api/v1/setup/check?allow=true", "valid", 400, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newSetupBrokerHTTPBoundary(t, "absent")
			body := &setupBrokerHTTPBody{}
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Body = body
			auth := tc.auth
			if auth == "valid" {
				auth = "Bearer " + b.token
			}
			req.Header.Set("Authorization", auth)
			req.Header.Set("Content-Type", "application/json")
			res := httptest.NewRecorder()
			b.handler.ServeHTTP(res, req)
			setupBrokerHTTPError(t, res, tc.status, tc.code)
			if body.reads != 0 {
				t.Fatalf("body reads=%d", body.reads)
			}
			b.noDispatch(t)
			b.noStateArtifacts(t)
		})
	}
}

func TestSetupBrokerHTTPUnrelatedV1CheckKeepsItsWire(t *testing.T) {
	for _, extra := range []string{"", "allow_github_installation_token_creation", "approve_github_source_broker_authority_identity"} {
		t.Run("extra_"+extra, func(t *testing.T) {
			b := newSetupBrokerHTTPBoundary(t, "current")
			value := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 1, "plan_identity": b.plan.Identity(), "key": "observer_credential_posture_validated", "confirmation": "run observer_credential_posture_validated"}
			if extra != "" {
				value[extra] = nil
			}
			res := b.serve(setupBrokerHTTPEncode(t, value), "application/json")
			if extra != "" {
				setupBrokerHTTPError(t, res, 400, "invalid_request")
				b.noDispatch(t)
				b.unchanged(t)
				return
			}
			if res.Code != 200 {
				t.Fatalf("response=%d %s", res.Code, res.Body.String())
			}
			plan, err := setupcore.InspectStateFile(context.Background(), b.path)
			if err != nil || len(plan.Receipts()) != 1 || plan.Receipts()[0].Key() != setupcore.CheckObserverCredentialPostureValidated || plan.Receipts()[0].State() != setupcore.CheckPassed {
				t.Fatalf("unrelated receipt=%v", err)
			}
			if b.builderCalls != 0 || b.probeCalls != 0 {
				t.Fatal("unrelated check reached integration")
			}
		})
	}
}

func TestSetupBrokerHTTPInitializeUsesCurrentCatalog(t *testing.T) {
	b := newSetupBrokerHTTPBoundary(t, "absent")
	value := map[string]any{"contract": "open-trestle/setup-init-request", "schema_version": 1, "profile": "controlled_hybrid", "tenant_id": b.tenant, "repository_id": b.repository, "recovery_owner": "owner", "confirmation": "create setup plan"}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/init", strings.NewReader(setupBrokerHTTPEncode(t, value)))
	req.Header.Set("Authorization", "Bearer "+b.token)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	b.handler.ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("initialize=%d %s", res.Code, res.Body.String())
	}
	plan, err := setupcore.InspectStateFile(context.Background(), b.path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, authority := range plan.CheckerAuthorities() {
		if authority.Key == setupcore.CheckIntegrationPermissionsValidated {
			found = true
			if authority.CheckerIdentity != setupBrokerHTTPCurrentChecker {
				t.Fatal("init installed historical integration authority")
			}
		}
	}
	if !found || len(plan.Receipts()) != 0 {
		t.Fatal("init missing current pending integration")
	}
	b.noDispatch(t)
	b.plan = plan
	b.resultReceipt(t, b.serve(b.wire(t), "application/json"), setupcore.CheckPassed)
	if b.builderCalls != 1 || b.probeCalls != 1 {
		t.Fatalf("builder=%d probe=%d", b.builderCalls, b.probeCalls)
	}
}

func TestSetupBrokerHTTPV2DoesNotUpgradeUnrelatedShape(t *testing.T) {
	b := newSetupBrokerHTTPBoundary(t, "absent")
	value := map[string]any{"contract": "open-trestle/setup-check-request", "schema_version": 2, "plan_identity": b.plan.Identity(), "key": "observer_credential_posture_validated", "confirmation": "run observer_credential_posture_validated"}
	setupBrokerHTTPError(t, b.serve(setupBrokerHTTPEncode(t, value), "application/json"), 400, "invalid_request")
	b.noDispatch(t)
	b.noStateArtifacts(t)
}
