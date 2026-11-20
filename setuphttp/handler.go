// Package setuphttp exposes a loopback-oriented authenticated API over protected setup state.
package setuphttp

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	providerconfig "github.com/georgejieh/open-trestle/internal/provider"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

const maxRequestBytes = 64 << 10

// Clock supplies canonical setup transition time.
type Clock interface{ Now() time.Time }

// IntegrationPermissionProbeBuilder constructs a request-scoped probe without creating credentials.
type IntegrationPermissionProbeBuilder func(plan setupcore.Plan, expectedBrokerAuthority string, allowTokenCreation bool) (setupcore.IntegrationPermissionProbe, error)

// WebhookProbeBuilder constructs one request-scoped local webhook conformance probe.
type WebhookProbeBuilder func(plan setupcore.Plan, keyID string) (setupcore.WebhookProbe, error)

// Options binds one handler to an exact state path and bearer authority.
type Options struct {
	StatePath                         string
	Token                             string
	Environment                       func(string) string
	LocalInferenceFactory             setupcore.LocalInferenceDispatcherFactory
	IntegrationPermissionProbeBuilder IntegrationPermissionProbeBuilder
	WebhookProbeBuilder               WebhookProbeBuilder
	Clock                             Clock
}

// Handler serves strict setup session, initialization, and check operations.
type Handler struct {
	statePath, token                  string
	environment                       func(string) string
	localInferenceFactory             setupcore.LocalInferenceDispatcherFactory
	integrationPermissionProbeBuilder IntegrationPermissionProbeBuilder
	webhookProbeBuilder               WebhookProbeBuilder
	clock                             Clock
}

// New constructs a handler without reading or creating setup state.
func New(options Options) (*Handler, error) {
	if !validRequestPath(options.StatePath) || !validToken(options.Token) || options.Environment == nil || nilInterface(options.Clock) || sameToken(options.Token, options.Environment("OPEN_TRESTLE_API_TOKEN")) || sameToken(options.Token, options.Environment("OPEN_TRESTLE_OBSERVER_TOKEN")) {
		return nil, errors.New("invalid setup HTTP configuration")
	}
	absolute, err := filepath.Abs(options.StatePath)
	if err != nil {
		return nil, errors.New("invalid setup HTTP configuration")
	}
	return &Handler{statePath: absolute, token: strings.Clone(options.Token), environment: options.Environment, localInferenceFactory: options.LocalInferenceFactory, integrationPermissionProbeBuilder: options.IntegrationPermissionProbeBuilder, webhookProbeBuilder: options.WebhookProbeBuilder, clock: options.Clock}, nil
}
func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setHeaders(writer.Header())
	if h == nil || request == nil || request.URL == nil {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if !h.authorized(request.Header.Get("Authorization")) {
		writeError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	if request.URL.RawQuery != "" || request.URL.Fragment != "" {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	switch request.URL.Path {
	case "/api/v1/setup":
		if request.Method != http.MethodGet {
			methodError(writer, http.MethodGet)
			return
		}
		h.session(writer, request)
	case "/api/v1/setup/init":
		if request.Method != http.MethodPost {
			methodError(writer, http.MethodPost)
			return
		}
		h.initialize(writer, request)
	case "/api/v1/setup/check":
		if request.Method != http.MethodPost {
			methodError(writer, http.MethodPost)
			return
		}
		h.check(writer, request)
	default:
		writeError(writer, http.StatusNotFound, "not_found")
	}
}
func (h *Handler) authorized(value string) bool {
	expected := "Bearer " + h.token
	return len(value) == len(expected) && subtle.ConstantTimeCompare([]byte(value), []byte(expected)) == 1
}
func (h *Handler) session(writer http.ResponseWriter, request *http.Request) {
	if request.ContentLength != 0 {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	_, err := os.Lstat(h.statePath)
	if os.IsNotExist(err) {
		writeSession(writer, http.StatusOK, nil)
		return
	}
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "state_unavailable")
		return
	}
	plan, err := setupcore.InspectStateFile(request.Context(), h.statePath)
	if err != nil {
		writeError(writer, http.StatusConflict, "state_invalid")
		return
	}
	writeSession(writer, http.StatusOK, &plan)
}

type initRequest struct {
	Contract      string `json:"contract"`
	SchemaVersion int    `json:"schema_version"`
	Profile       string `json:"profile"`
	TenantID      string `json:"tenant_id"`
	RepositoryID  string `json:"repository_id"`
	RecoveryOwner string `json:"recovery_owner"`
	Confirmation  string `json:"confirmation"`
}

func (h *Handler) initialize(writer http.ResponseWriter, request *http.Request) {
	var value initRequest
	_, status := decodeRequest(request, &value)
	if status != 0 {
		writeError(writer, status, requestErrorCode(status))
		return
	}
	if value.Contract != "open-trestle/setup-init-request" || value.SchemaVersion != 1 || value.Confirmation != "create setup plan" {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	profile, err := setupcore.ParseProfile(value.Profile)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	plan, err := setupcore.NewCurrentPlan(profile, value.TenantID, value.RepositoryID, value.RecoveryOwner, h.clock.Now())
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	state, err := setupcore.OpenStateFile(h.statePath)
	if err != nil {
		writeError(writer, http.StatusConflict, "state_conflict")
		return
	}
	defer state.Close()
	if err = state.Initialize(request.Context(), plan); err != nil {
		writeError(writer, http.StatusConflict, "state_conflict")
		return
	}
	writeSession(writer, http.StatusCreated, &plan)
}

type checkRequest struct {
	Contract                                      string `json:"contract"`
	SchemaVersion                                 int    `json:"schema_version"`
	PlanIdentity                                  string `json:"plan_identity"`
	Key                                           string `json:"key"`
	Confirmation                                  string `json:"confirmation"`
	StorageRoot                                   string `json:"storage_root"`
	BackupSnapshotPath                            string `json:"backup_snapshot_path"`
	RouteInventoryPath                            string `json:"route_inventory_path"`
	RuntimePolicyPath                             string `json:"runtime_policy_path"`
	ApproveInventoryIdentity                      string `json:"approve_inventory_identity"`
	ApproveRuntimePolicyIdentity                  string `json:"approve_runtime_policy_identity"`
	ApproveReviewPolicyIdentity                   string `json:"approve_review_policy_identity"`
	ApproveIntegrationPermissionAuthorityIdentity string `json:"approve_integration_permission_authority_identity"`
	ApproveGitHubSourceBrokerAuthorityIdentity    string `json:"approve_github_source_broker_authority_identity"`
	AllowGitHubInstallationTokenCreation          bool   `json:"allow_github_installation_token_creation"`
	ApproveWebhookAuthorityIdentity               string `json:"approve_webhook_authority_identity"`
	GitHubAPIEndpoint                             string `json:"github_api_endpoint"`
	GitHubAPIVersion                              string `json:"github_api_version"`
	GitHubInstallationID                          uint64 `json:"github_installation_id"`
	GitHubRepositoryFullName                      string `json:"github_repository_full_name"`
	GitHubWebhookKeyID                            string `json:"github_webhook_key_id"`
	ApprovedBy                                    string `json:"approved_by"`
}

func (h *Handler) check(writer http.ResponseWriter, request *http.Request) {
	var value checkRequest
	fields, status := decodeRequest(request, &value)
	if status != 0 {
		writeError(writer, status, requestErrorCode(status))
		return
	}
	key := setupcore.CheckKey(value.Key)
	if value.Contract != "open-trestle/setup-check-request" || !validDigest(value.PlanIdentity) || !validCheckShape(key, value, fields) {
		writeError(writer, http.StatusBadRequest, "invalid_request")
		return
	}
	if value.SchemaVersion == 1 && key == setupcore.CheckIntegrationPermissionsValidated {
		writeError(writer, http.StatusUnprocessableEntity, "check_unavailable")
		return
	}
	if _, err := setupcore.InspectStateFile(request.Context(), h.statePath); err != nil {
		writeError(writer, http.StatusConflict, "state_conflict")
		return
	}
	state, err := setupcore.OpenStateFile(h.statePath)
	if err != nil {
		writeError(writer, http.StatusConflict, "state_conflict")
		return
	}
	defer state.Close()
	plan, err := state.Current(request.Context())
	if err != nil || plan.Identity() != value.PlanIdentity {
		writeError(writer, http.StatusConflict, "stale_plan")
		return
	}
	checker, err := h.checker(plan, key, value)
	if err != nil {
		writeError(writer, http.StatusUnprocessableEntity, "check_unavailable")
		return
	}
	runner, err := setupcore.NewRunner(state, []setupcore.Checker{checker}, h.clock)
	if err != nil {
		writeError(writer, http.StatusUnprocessableEntity, "check_unavailable")
		return
	}
	next, receipt, err := runner.RunExpected(request.Context(), key, value.PlanIdentity)
	if err != nil {
		status := http.StatusUnprocessableEntity
		code := "check_failed"
		if errors.Is(err, setupcore.ErrStateConflict) || errors.Is(err, setupcore.ErrStaleCheckReceipt) {
			status, code = http.StatusConflict, "stale_plan"
		}
		writeError(writer, status, code)
		return
	}
	writeCheckResult(writer, next, receipt)
}
func (h *Handler) checker(plan setupcore.Plan, key setupcore.CheckKey, value checkRequest) (setupcore.Checker, error) {
	switch key {
	case setupcore.CheckStateStoragePostureValidated:
		return setupcore.NewStateStorageChecker(value.StorageRoot)
	case setupcore.CheckObserverCredentialPostureValidated:
		return setupcore.NewObserverCredentialPostureChecker(h.environment)
	case setupcore.CheckLocalAdministratorValidated:
		return setupcore.NewLocalAdministratorChecker(plan, value.ApprovedBy)
	case setupcore.CheckBackupValidated:
		return setupcore.NewBackupSnapshotChecker(h.statePath, value.BackupSnapshotPath, plan)
	case setupcore.CheckIntegrationPermissionsValidated:
		if h.integrationPermissionProbeBuilder == nil {
			return nil, errors.New("integration permission setup probe unavailable")
		}
		probe, err := h.integrationPermissionProbeBuilder(plan, value.ApproveGitHubSourceBrokerAuthorityIdentity, value.AllowGitHubInstallationTokenCreation)
		if err != nil {
			return nil, err
		}
		return setupcore.NewIntegrationPermissionChecker(plan, value.ApproveIntegrationPermissionAuthorityIdentity, value.ApprovedBy, probe)
	case setupcore.CheckWebhookValidated:
		if h.webhookProbeBuilder == nil {
			return nil, errors.New("webhook setup probe unavailable")
		}
		probe, err := h.webhookProbeBuilder(plan, value.GitHubWebhookKeyID)
		if err != nil {
			return nil, err
		}
		return setupcore.NewWebhookChecker(plan, value.ApproveWebhookAuthorityIdentity, value.ApprovedBy, probe)
	case setupcore.CheckRemoteProviderAuthorized, setupcore.CheckPolicyValidated, setupcore.CheckDryRunValidated, setupcore.CheckLocalInferenceValidated:
		approval, err := setupcore.NewRuntimePolicyApproval(plan, value.ApproveInventoryIdentity, value.ApproveRuntimePolicyIdentity, value.ApproveReviewPolicyIdentity, value.ApprovedBy)
		if err != nil {
			return nil, err
		}
		policy, err := setupcore.NewRuntimePolicyFileChecker(value.RouteInventoryPath, value.RuntimePolicyPath, approval)
		if err != nil {
			return nil, err
		}
		if key == setupcore.CheckRemoteProviderAuthorized {
			return setupcore.NewRemoteProviderAuthorizationChecker(policy)
		}
		if key == setupcore.CheckDryRunValidated {
			return setupcore.NewDryRunChecker(policy)
		}
		if key == setupcore.CheckLocalInferenceValidated {
			if nilInterface(h.localInferenceFactory) {
				return nil, errors.New("local inference unavailable")
			}
			return setupcore.NewLocalInferenceChecker(policy, h.localInferenceFactory)
		}
		return policy, nil
	default:
		return nil, errors.New("unsupported setup check")
	}
}
func validCheckShape(key setupcore.CheckKey, value checkRequest, fields map[string]struct{}) bool {
	if value.SchemaVersion == 2 {
		return key == setupcore.CheckIntegrationPermissionsValidated && validBrokerIntegrationCheckShape(value, fields)
	}
	if value.SchemaVersion != 1 || value.Confirmation != "run "+value.Key {
		return false
	}
	present := func(name string) bool { _, ok := fields[name]; return ok }
	if present("approve_github_source_broker_authority_identity") || present("allow_github_installation_token_creation") {
		return false
	}
	hasStorage := present("storage_root")
	hasBackup := present("backup_snapshot_path")
	hasApproval := present("approved_by")
	hasIntegrationAuthority := present("approve_integration_permission_authority_identity")
	hasGitHubEndpoint := present("github_api_endpoint")
	hasGitHubVersion := present("github_api_version")
	hasGitHubInstallation := present("github_installation_id")
	hasGitHubRepository := present("github_repository_full_name")
	anyIntegration := hasIntegrationAuthority || hasGitHubEndpoint || hasGitHubVersion || hasGitHubInstallation || hasGitHubRepository
	hasWebhookAuthority := present("approve_webhook_authority_identity")
	hasWebhookKeyID := present("github_webhook_key_id")
	anyWebhook := hasWebhookAuthority || hasWebhookKeyID
	policyNames := []string{"route_inventory_path", "runtime_policy_path", "approve_inventory_identity", "approve_runtime_policy_identity", "approve_review_policy_identity"}
	anyPolicy, allPolicy := false, true
	for _, name := range policyNames {
		found := present(name)
		anyPolicy = anyPolicy || found
		allPolicy = allPolicy && found
	}
	completeIntegration := hasIntegrationAuthority && hasGitHubEndpoint && hasGitHubVersion && hasGitHubInstallation && hasGitHubRepository && validDigest(value.ApproveIntegrationPermissionAuthorityIdentity) && validGitHubPermissionEndpoint(value.GitHubAPIEndpoint) && validGitHubPermissionVersion(value.GitHubAPIVersion) && value.GitHubInstallationID > 0 && value.GitHubInstallationID <= 9_007_199_254_740_991 && validGitHubPermissionRepository(value.GitHubRepositoryFullName) && hasApproval && validLabel(value.ApprovedBy)
	completeWebhook := hasWebhookAuthority && hasWebhookKeyID && validDigest(value.ApproveWebhookAuthorityIdentity) && validSecretInput(value.GitHubWebhookKeyID, 128) && hasApproval && validLabel(value.ApprovedBy)
	completePolicy := allPolicy && hasApproval && validRequestPath(value.RouteInventoryPath) && validRequestPath(value.RuntimePolicyPath) && validDigest(value.ApproveInventoryIdentity) && validDigest(value.ApproveRuntimePolicyIdentity) && validDigest(value.ApproveReviewPolicyIdentity) && validLabel(value.ApprovedBy)
	switch key {
	case setupcore.CheckStateStoragePostureValidated:
		return hasStorage && validRequestPath(value.StorageRoot) && !hasBackup && !hasApproval && !anyPolicy && !anyIntegration && !anyWebhook
	case setupcore.CheckObserverCredentialPostureValidated:
		return !hasStorage && !hasBackup && !hasApproval && !anyPolicy && !anyIntegration && !anyWebhook
	case setupcore.CheckLocalAdministratorValidated:
		return !hasStorage && !hasBackup && hasApproval && validLabel(value.ApprovedBy) && !anyPolicy && !anyIntegration && !anyWebhook
	case setupcore.CheckBackupValidated:
		return !hasStorage && hasBackup && validRequestPath(value.BackupSnapshotPath) && !hasApproval && !anyPolicy && !anyIntegration && !anyWebhook
	case setupcore.CheckIntegrationPermissionsValidated:
		return !hasStorage && !hasBackup && !anyPolicy && completeIntegration && !anyWebhook
	case setupcore.CheckWebhookValidated:
		return !hasStorage && !hasBackup && !anyPolicy && !anyIntegration && completeWebhook
	case setupcore.CheckRemoteProviderAuthorized, setupcore.CheckPolicyValidated, setupcore.CheckDryRunValidated, setupcore.CheckLocalInferenceValidated:
		return !hasStorage && !hasBackup && completePolicy && !anyIntegration && !anyWebhook
	default:
		return false
	}
}
func validBrokerIntegrationCheckShape(value checkRequest, fields map[string]struct{}) bool {
	required := [...]string{
		"contract", "schema_version", "plan_identity", "key", "confirmation",
		"approve_integration_permission_authority_identity",
		"approve_github_source_broker_authority_identity",
		"allow_github_installation_token_creation", "approved_by",
	}
	if len(fields) != len(required) {
		return false
	}
	for _, name := range required {
		if _, present := fields[name]; !present {
			return false
		}
	}
	return value.Contract == "open-trestle/setup-check-request" && value.SchemaVersion == 2 &&
		value.Key == string(setupcore.CheckIntegrationPermissionsValidated) &&
		value.Confirmation == "create GitHub installation token and run integration_permissions_validated" &&
		validDigest(value.PlanIdentity) && validDigest(value.ApproveIntegrationPermissionAuthorityIdentity) &&
		validDigest(value.ApproveGitHubSourceBrokerAuthorityIdentity) && value.AllowGitHubInstallationTokenCreation &&
		validLabel(value.ApprovedBy)
}
func validGitHubPermissionEndpoint(value string) bool {
	endpoint, err := providerconfig.ParseServiceEndpoint(value)
	if err != nil || endpoint == nil {
		return false
	}
	_, err = providerconfig.ClassifyServiceEndpoint(value)
	return err == nil
}
func validGitHubPermissionVersion(value string) bool {
	if len(value) != 10 || value[:4] < "2000" {
		return false
	}
	parsed, err := time.Parse("2006-01-02", value)
	return err == nil && parsed.Format("2006-01-02") == value
}
func validGitHubPermissionRepository(value string) bool {
	owner, name, found := strings.Cut(value, "/")
	return found && !strings.Contains(name, "/") && validGitHubPermissionSlug(owner) && validGitHubPermissionSlug(name)
}
func validGitHubPermissionSlug(value string) bool {
	if len(value) == 0 || len(value) > 255 {
		return false
	}
	for _, candidate := range value {
		if !(candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9' || candidate == '.' || candidate == '_' || candidate == '-') {
			return false
		}
	}
	return true
}
func validSecretInput(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, candidate := range value {
		if candidate < 0x21 || candidate == 0x7f {
			return false
		}
	}
	return true
}
func decodeRequest(request *http.Request, target any) (map[string]struct{}, int) {
	mediaType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	charset, hasCharset := parameters["charset"]
	if err != nil || mediaType != "application/json" || len(parameters) > 1 || len(parameters) == 1 && (!hasCharset || !strings.EqualFold(charset, "utf-8")) {
		return nil, http.StatusUnsupportedMediaType
	}
	content, err := io.ReadAll(io.LimitReader(request.Body, maxRequestBytes+1))
	if err != nil {
		return nil, http.StatusBadRequest
	}
	if len(content) > maxRequestBytes {
		return nil, http.StatusRequestEntityTooLarge
	}
	if len(content) == 0 || !utf8.Valid(content) || uniqueJSON(content) != nil {
		return nil, http.StatusBadRequest
	}
	fields, ok := exactRequestKeys(content, target)
	if !ok {
		return nil, http.StatusBadRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, http.StatusBadRequest
	}
	return fields, 0
}
func exactRequestKeys(content []byte, target any) (map[string]struct{}, bool) {
	candidate := reflect.TypeOf(target)
	if candidate == nil || candidate.Kind() != reflect.Pointer || candidate.Elem().Kind() != reflect.Struct {
		return nil, false
	}
	candidate = candidate.Elem()
	allowed := make(map[string]bool, candidate.NumField())
	for index := 0; index < candidate.NumField(); index++ {
		tag := candidate.Field(index).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			return nil, false
		}
		allowed[name] = true
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(content, &object) != nil || object == nil {
		return nil, false
	}
	fields := make(map[string]struct{}, len(object))
	for name := range object {
		if !allowed[name] {
			return nil, false
		}
		fields[name] = struct{}{}
	}
	return fields, true
}

func uniqueJSON(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := scanJSON(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func scanJSON(decoder *json.Decoder, depth int) error {
	if depth > 128 {
		return errors.New("JSON nesting too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			token, err = decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return errors.New("ambiguous JSON")
			}
			seen[key] = true
			if err = scanJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		token, err = decoder.Token()
		if err != nil || token != json.Delim('}') {
			return errors.New("invalid JSON")
		}
	case '[':
		for decoder.More() {
			if err = scanJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		token, err = decoder.Token()
		if err != nil || token != json.Delim(']') {
			return errors.New("invalid JSON")
		}
	default:
		return errors.New("invalid JSON")
	}
	return nil
}
func writeSession(writer http.ResponseWriter, status int, plan *setupcore.Plan) {
	var raw json.RawMessage
	if plan != nil {
		encoded, err := setupcore.EncodePlan(*plan)
		if err != nil {
			writeError(writer, http.StatusInternalServerError, "encode_failed")
			return
		}
		raw = encoded
	}
	response := struct {
		Contract      string          `json:"contract"`
		SchemaVersion int             `json:"schema_version"`
		Initialized   bool            `json:"initialized"`
		Plan          json.RawMessage `json:"plan,omitempty"`
	}{"open-trestle/setup-session", 1, plan != nil, raw}
	writeJSON(writer, status, response)
}
func writeCheckResult(writer http.ResponseWriter, plan setupcore.Plan, receipt setupcore.CheckReceipt) {
	planBytes, planErr := setupcore.EncodePlan(plan)
	receiptBytes, receiptErr := setupcore.EncodeCheckReceipt(receipt)
	if planErr != nil || receiptErr != nil {
		writeError(writer, http.StatusInternalServerError, "encode_failed")
		return
	}
	response := struct {
		Contract      string          `json:"contract"`
		SchemaVersion int             `json:"schema_version"`
		Plan          json.RawMessage `json:"plan"`
		Receipt       json.RawMessage `json:"receipt"`
	}{"open-trestle/setup-check-result", 1, planBytes, receiptBytes}
	writeJSON(writer, http.StatusOK, response)
}
func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
func writeError(writer http.ResponseWriter, status int, code string) {
	writeJSON(writer, status, struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		Code          string `json:"code"`
	}{"open-trestle/setup-error", 1, code})
}
func methodError(writer http.ResponseWriter, allowed string) {
	writer.Header().Set("Allow", allowed)
	writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
}
func requestErrorCode(status int) string {
	if status == http.StatusRequestEntityTooLarge {
		return "request_too_large"
	}
	if status == http.StatusUnsupportedMediaType {
		return "unsupported_media_type"
	}
	return "invalid_request"
}
func setHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	header.Set("Cross-Origin-Opener-Policy", "same-origin")
	header.Set("Cross-Origin-Resource-Policy", "same-origin")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}
func sameToken(left, right string) bool {
	return right != "" && len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	candidate := reflect.ValueOf(value)
	switch candidate.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return candidate.IsNil()
	}
	return false
}
func validRequestPath(value string) bool {
	if len(value) == 0 || len(value) > 4096 {
		return false
	}
	for _, character := range value {
		if character == 0 || character == '\r' || character == '\n' {
			return false
		}
	}
	return true
}
func validLabel(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character == '-' || character == '_' || character == '.' || character == ':' || character == '@' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}
func validToken(value string) bool {
	if len(value) < 32 || len(value) > 512 || strings.TrimSpace(value) != value {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}
func validDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) || value == strings.Repeat("0", 64) {
		return false
	}
	for _, candidate := range value {
		if !(candidate >= '0' && candidate <= '9' || candidate >= 'a' && candidate <= 'f') {
			return false
		}
	}
	return true
}
func (h *Handler) String() string   { return "setup HTTP handler" }
func (h *Handler) GoString() string { return "setuphttp.Handler{<redacted>}" }
func (h *Handler) Format(state fmt.State, verb rune) {
	value := h.String()
	if verb == 'q' {
		value = fmt.Sprintf("%q", value)
	} else if verb == 'v' && state.Flag('#') {
		value = h.GoString()
	}
	_, _ = state.Write([]byte(value))
}
