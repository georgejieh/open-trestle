// Package client provides a transport client for the Open Trestle review-run API.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/apilimit"
	"github.com/georgejieh/open-trestle/runtimeadmin"
)

const (
	maxClientResponseBytes   = apilimit.MaximumResponseBytes
	minClientCredentialBytes = 32
	maxClientCredentialBytes = 512
	defaultClientTimeout     = 30 * time.Second
	maxClientTimeout         = 2 * time.Minute
)

var (
	// ErrInvalidClient identifies unsafe endpoint, credential, or HTTP settings.
	ErrInvalidClient = errors.New("invalid Open Trestle client")
	// ErrInvalidResponse identifies malformed, excessive, or unexpected server output.
	ErrInvalidResponse = errors.New("invalid Open Trestle API response")
	// ErrRedirectRejected identifies a redirect that could disclose authority.
	ErrRedirectRejected = errors.New("Open Trestle API redirect rejected")
)

// Client invokes the versioned review-run API without forwarding credentials across redirects.
type Client struct {
	baseURL    *url.URL
	credential string
	httpClient *http.Client
}

func New(rawBaseURL, credential string, httpClient *http.Client) (*Client, error) {
	baseURL, err := url.Parse(rawBaseURL)
	if err != nil || !validBaseURL(baseURL) || !validClientCredential(credential) {
		return nil, ErrInvalidClient
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultClientTimeout}
	}
	clone := *httpClient
	if clone.Timeout == 0 {
		clone.Timeout = defaultClientTimeout
	}
	if clone.Timeout < 0 || clone.Timeout > maxClientTimeout {
		return nil, ErrInvalidClient
	}
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrRedirectRejected }
	baseCopy := *baseURL
	baseCopy.Path = ""
	baseCopy.RawPath = ""
	return &Client{baseURL: &baseCopy, credential: strings.Clone(credential), httpClient: &clone}, nil
}
func (c *Client) SubmitRun(ctx context.Context, plan controlplane.ReviewRunPlan) (controlplane.ReviewRunReceipt, error) {
	if err := plan.Validate(); err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	encoded, err := controlplane.EncodeReviewRunPlan(plan)
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	receipt, err := c.doReceipt(ctx, http.MethodPost, "/api/v1/runs", encoded, http.StatusAccepted, plan.Scope())
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	if receipt.PlanIdentity() != plan.Identity() {
		return controlplane.ReviewRunReceipt{}, ErrInvalidResponse
	}
	return receipt, nil
}
func (c *Client) GetRun(ctx context.Context, scope audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	if err := scope.Validate(); err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	return c.doReceipt(ctx, http.MethodGet, runPath(scope), nil, http.StatusOK, scope)
}

// GetRunPlan reads the exact immutable plan for one authorized run.
func (c *Client) GetRunPlan(ctx context.Context, scope audit.ReviewScope) (controlplane.ReviewRunPlan, error) {
	if err := scope.Validate(); err != nil {
		return controlplane.ReviewRunPlan{}, err
	}
	record, err := c.request(ctx, http.MethodGet, runPath(scope)+"/plan", nil, http.StatusOK)
	if err != nil {
		return controlplane.ReviewRunPlan{}, err
	}
	if record.Error != nil || len(record.Plan) == 0 || len(record.Run) != 0 || len(record.Lease) != 0 || len(record.Diagnostics) != 0 {
		return controlplane.ReviewRunPlan{}, ErrInvalidResponse
	}
	plan, err := controlplane.ParseReviewRunPlan(record.Plan)
	if err != nil || plan.Scope().Identity() != scope.Identity() {
		return controlplane.ReviewRunPlan{}, ErrInvalidResponse
	}
	return plan, nil
}

// GetDiagnosticSet reads independently verified diagnostics for one exact run scope.
func (c *Client) GetDiagnosticSet(ctx context.Context, scope audit.ReviewScope) (diagnostics.Set, error) {
	if err := scope.Validate(); err != nil {
		return diagnostics.Set{}, err
	}
	record, err := c.request(ctx, http.MethodGet, runPath(scope)+"/diagnostics", nil, http.StatusOK)
	if err != nil {
		return diagnostics.Set{}, err
	}
	if record.Error != nil || len(record.Diagnostics) == 0 || len(record.Run) != 0 || len(record.Plan) != 0 || len(record.Lease) != 0 {
		return diagnostics.Set{}, ErrInvalidResponse
	}
	set, err := diagnostics.ParseSet(record.Diagnostics)
	if err != nil || set.Scope().Identity() != scope.Identity() {
		return diagnostics.Set{}, ErrInvalidResponse
	}
	return set, nil
}

// GetRuntimeStatus reads one repository-scoped, content-free administration snapshot.
func (c *Client) GetRuntimeStatus(ctx context.Context, tenantID, repositoryID string) (runtimeadmin.Snapshot, error) {
	if _, err := audit.NewReviewScope(tenantID, repositoryID, "runtime-status"); err != nil {
		return runtimeadmin.Snapshot{}, ErrInvalidClient
	}
	if c == nil || c.baseURL == nil || c.httpClient == nil || ctx == nil {
		return runtimeadmin.Snapshot{}, ErrInvalidClient
	}
	requestURL := *c.baseURL
	requestURL.Path = "/api/v1/tenants/" + url.PathEscape(tenantID) + "/repositories/" + url.PathEscape(repositoryID) + "/runtime"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return runtimeadmin.Snapshot{}, ErrInvalidClient
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.credential)
	request.Header.Set("User-Agent", "open-trestle-client/1")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if errors.Is(err, ErrRedirectRejected) {
			return runtimeadmin.Snapshot{}, ErrRedirectRejected
		}
		return runtimeadmin.Snapshot{}, fmt.Errorf("Open Trestle API request: %w", err)
	}
	defer response.Body.Close()
	encoded, tooLarge, readErr := readClientBody(response.Body)
	if readErr != nil || tooLarge {
		return runtimeadmin.Snapshot{}, ErrInvalidResponse
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		return runtimeadmin.Snapshot{}, ErrInvalidResponse
	}
	if response.StatusCode != http.StatusOK {
		record, parseErr := parseClientResponse(encoded)
		if parseErr != nil || record.Error == nil {
			return runtimeadmin.Snapshot{}, ErrInvalidResponse
		}
		return runtimeadmin.Snapshot{}, &APIError{statusCode: response.StatusCode, requestID: record.RequestID, code: record.Error.Code, message: record.Error.Message}
	}
	var envelope struct {
		Contract      string          `json:"contract"`
		SchemaVersion int             `json:"schema_version"`
		RequestID     string          `json:"request_id"`
		Status        json.RawMessage `json:"status"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) != io.EOF || envelope.Contract != "open-trestle/runtime-status-response" || envelope.SchemaVersion != 1 || !validResponseValue(envelope.RequestID, 128) || len(envelope.Status) == 0 {
		return runtimeadmin.Snapshot{}, ErrInvalidResponse
	}
	snapshot, err := runtimeadmin.DecodeSnapshot(envelope.Status)
	if err != nil || snapshot.TenantID() != tenantID || snapshot.RepositoryID() != repositoryID {
		return runtimeadmin.Snapshot{}, ErrInvalidResponse
	}
	return snapshot, nil
}

func (c *Client) CancelRun(ctx context.Context, scope audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	if err := scope.Validate(); err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	return c.doReceipt(ctx, http.MethodPost, runPath(scope)+"/cancel", nil, http.StatusOK, scope)
}

// FinalizeRun records the terminal run output or closed failure after all required work settles.
func (c *Client) FinalizeRun(ctx context.Context, scope audit.ReviewScope, completion controlplane.TaskCompletion) (controlplane.ReviewRunReceipt, error) {
	if err := scope.Validate(); err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	if err := completion.Validate(); err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	body, err := controlplane.EncodeTaskCompletion(completion)
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	return c.doReceipt(ctx, http.MethodPost, runPath(scope)+"/finalize", body, http.StatusOK, scope)
}

// ClaimTask acquires one task using the exact handler identity bound into its plan.
func (c *Client) ClaimTask(ctx context.Context, scope audit.ReviewScope, taskKey, handlerIdentity string) (controlplane.TaskLease, error) {
	if err := scope.Validate(); err != nil {
		return controlplane.TaskLease{}, err
	}
	if controlplane.ValidateTaskKey(taskKey) != nil || controlplane.ValidateHandlerIdentity(handlerIdentity) != nil {
		return controlplane.TaskLease{}, ErrInvalidClient
	}
	body, _ := json.Marshal(taskClaimRequest{Contract: "open-trestle/task-claim-request", SchemaVersion: 1, HandlerIdentity: handlerIdentity})
	return c.doLease(ctx, http.MethodPost, workerPath(scope, taskKey)+"/claim", body)
}

// RenewTaskLease extends one current worker capability.
func (c *Client) RenewTaskLease(ctx context.Context, scope audit.ReviewScope, lease controlplane.TaskLease) (controlplane.TaskLease, error) {
	if err := scope.Validate(); err != nil {
		return controlplane.TaskLease{}, err
	}
	if err := lease.Validate(); err != nil {
		return controlplane.TaskLease{}, err
	}
	body, err := controlplane.EncodeTaskLease(lease)
	if err != nil {
		return controlplane.TaskLease{}, err
	}
	return c.doLease(ctx, http.MethodPost, workerPath(scope, lease.TaskKey())+"/renew", body)
}

// CompleteTask records a closed worker result and returns the advanced run state.
func (c *Client) CompleteTask(ctx context.Context, scope audit.ReviewScope, lease controlplane.TaskLease, completion controlplane.TaskCompletion) (controlplane.ReviewRunReceipt, error) {
	if err := scope.Validate(); err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	if err := lease.Validate(); err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	if err := completion.Validate(); err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	encodedLease, _ := controlplane.EncodeTaskLease(lease)
	encodedCompletion, _ := controlplane.EncodeTaskCompletion(completion)
	body, _ := json.Marshal(taskCompletionRequest{Contract: "open-trestle/task-completion-request", SchemaVersion: 1, Lease: encodedLease, Completion: encodedCompletion})
	return c.doReceipt(ctx, http.MethodPost, workerPath(scope, lease.TaskKey())+"/complete", body, http.StatusOK, scope)
}

// ClaimTaskNotification waits for and leases one non-authoritative scheduling hint.
func (c *Client) ClaimTaskNotification(ctx context.Context, scope audit.ReviewScope, wait, leaseDuration time.Duration) (controlplane.TaskNotificationLease, bool, error) {
	if scope.Validate() != nil || wait < 0 || wait > 10*time.Second || wait%time.Millisecond != 0 || leaseDuration < time.Second || leaseDuration > 24*time.Hour || leaseDuration%time.Millisecond != 0 {
		return controlplane.TaskNotificationLease{}, false, ErrInvalidClient
	}
	body, _ := json.Marshal(taskNotificationClaimRequest{Contract: "open-trestle/task-notification-claim-request", SchemaVersion: 1, WaitMilliseconds: uint32(wait / time.Millisecond), LeaseDurationMilliseconds: uint32(leaseDuration / time.Millisecond)})
	record, status, err := c.requestStatuses(ctx, http.MethodPost, runPath(scope)+"/worker/notifications/claim", body, http.StatusOK, http.StatusNoContent)
	if err != nil {
		return controlplane.TaskNotificationLease{}, false, err
	}
	if status == http.StatusNoContent {
		return controlplane.TaskNotificationLease{}, false, nil
	}
	if record.Error != nil || len(record.Lease) == 0 || len(record.Run) != 0 || len(record.Plan) != 0 || len(record.Diagnostics) != 0 {
		return controlplane.TaskNotificationLease{}, false, ErrInvalidResponse
	}
	lease, err := controlplane.ParseTaskNotificationLease(record.Lease)
	if err != nil || lease.Notification().Scope().Identity() != scope.Identity() {
		return controlplane.TaskNotificationLease{}, false, ErrInvalidResponse
	}
	return lease, true, nil
}

// AcknowledgeTaskNotification settles one current queue delivery capability.
func (c *Client) AcknowledgeTaskNotification(ctx context.Context, scope audit.ReviewScope, lease controlplane.TaskNotificationLease) error {
	if scope.Validate() != nil || lease.Validate() != nil || lease.Notification().Scope().Identity() != scope.Identity() {
		return ErrInvalidClient
	}
	body, err := controlplane.EncodeTaskNotificationLease(lease)
	if err != nil {
		return err
	}
	record, status, err := c.requestStatuses(ctx, http.MethodPost, runPath(scope)+"/worker/notifications/acknowledge", body, http.StatusNoContent)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent || record.Contract != "" || record.SchemaVersion != 0 || record.RequestID != "" || len(record.Run) != 0 || len(record.Plan) != 0 || len(record.Lease) != 0 || len(record.Diagnostics) != 0 || record.Error != nil {
		return ErrInvalidResponse
	}
	return nil
}

type taskNotificationClaimRequest struct {
	Contract                  string `json:"contract"`
	SchemaVersion             int    `json:"schema_version"`
	WaitMilliseconds          uint32 `json:"wait_milliseconds"`
	LeaseDurationMilliseconds uint32 `json:"lease_duration_milliseconds"`
}

type taskClaimRequest struct {
	Contract        string `json:"contract"`
	SchemaVersion   int    `json:"schema_version"`
	HandlerIdentity string `json:"handler_identity"`
}
type taskCompletionRequest struct {
	Contract      string          `json:"contract"`
	SchemaVersion int             `json:"schema_version"`
	Lease         json.RawMessage `json:"lease"`
	Completion    json.RawMessage `json:"completion"`
}

func (c *Client) doLease(ctx context.Context, method, path string, body []byte) (controlplane.TaskLease, error) {
	record, err := c.request(ctx, method, path, body, http.StatusOK)
	if err != nil {
		return controlplane.TaskLease{}, err
	}
	if record.Error != nil || len(record.Lease) == 0 || len(record.Run) != 0 || len(record.Plan) != 0 || len(record.Diagnostics) != 0 {
		return controlplane.TaskLease{}, ErrInvalidResponse
	}
	lease, err := controlplane.ParseTaskLease(record.Lease)
	if err != nil {
		return controlplane.TaskLease{}, ErrInvalidResponse
	}
	return lease, nil
}
func (c *Client) doReceipt(ctx context.Context, method, path string, body []byte, wantStatus int, scope audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	record, err := c.request(ctx, method, path, body, wantStatus)
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	if record.Error != nil || len(record.Run) == 0 || len(record.Plan) != 0 || len(record.Lease) != 0 || len(record.Diagnostics) != 0 {
		return controlplane.ReviewRunReceipt{}, ErrInvalidResponse
	}
	receipt, err := controlplane.ParseReviewRunReceipt(record.Run)
	if err != nil || receipt.Scope().Identity() != scope.Identity() {
		return controlplane.ReviewRunReceipt{}, ErrInvalidResponse
	}
	return receipt, nil
}
func (c *Client) request(ctx context.Context, method, path string, body []byte, wantStatus int) (clientResponseRecord, error) {
	record, _, err := c.requestStatuses(ctx, method, path, body, wantStatus)
	return record, err
}
func (c *Client) requestStatuses(ctx context.Context, method, path string, body []byte, wantStatuses ...int) (clientResponseRecord, int, error) {
	if c == nil || c.baseURL == nil || c.httpClient == nil || ctx == nil {
		return clientResponseRecord{}, 0, ErrInvalidClient
	}
	requestURL := *c.baseURL
	requestURL.Path = path
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), reader)
	if err != nil {
		return clientResponseRecord{}, 0, ErrInvalidClient
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.credential)
	request.Header.Set("User-Agent", "open-trestle-client/1")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		if errors.Is(err, ErrRedirectRejected) {
			return clientResponseRecord{}, 0, ErrRedirectRejected
		}
		return clientResponseRecord{}, 0, fmt.Errorf("Open Trestle API request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNoContent {
		encoded, tooLarge, readErr := readClientBody(response.Body)
		if readErr != nil || tooLarge || len(encoded) != 0 {
			return clientResponseRecord{}, response.StatusCode, ErrInvalidResponse
		}
		allowed := false
		for _, status := range wantStatuses {
			if status == http.StatusNoContent {
				allowed = true
				break
			}
		}
		if !allowed {
			return clientResponseRecord{}, response.StatusCode, ErrInvalidResponse
		}
		return clientResponseRecord{}, response.StatusCode, nil
	}
	encoded, tooLarge, readErr := readClientBody(response.Body)
	if readErr != nil || tooLarge {
		return clientResponseRecord{}, 0, ErrInvalidResponse
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		return clientResponseRecord{}, 0, ErrInvalidResponse
	}
	record, parseErr := parseClientResponse(encoded)
	if parseErr != nil {
		return clientResponseRecord{}, 0, parseErr
	}
	allowed := false
	for _, status := range wantStatuses {
		if response.StatusCode == status {
			allowed = true
			break
		}
	}
	if !allowed {
		if record.Error == nil {
			return clientResponseRecord{}, response.StatusCode, ErrInvalidResponse
		}
		return clientResponseRecord{}, response.StatusCode, &APIError{statusCode: response.StatusCode, requestID: record.RequestID, code: record.Error.Code, message: record.Error.Message}
	}
	return record, response.StatusCode, nil
}
func (c *Client) String() string   { return "Open Trestle client" }
func (c *Client) GoString() string { return "client.Client{<redacted>}" }
func (c *Client) Format(state fmt.State, verb rune) {
	formatted := "Open Trestle client"
	if verb == 'q' {
		formatted = `"Open Trestle client"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "client.Client{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// APIError is a bounded public error returned by the daemon.
type APIError struct {
	statusCode               int
	requestID, code, message string
}

func (e *APIError) StatusCode() int {
	if e == nil {
		return 0
	}
	return e.statusCode
}
func (e *APIError) RequestID() string {
	if e == nil {
		return ""
	}
	return e.requestID
}
func (e *APIError) Code() string {
	if e == nil {
		return ""
	}
	return e.code
}
func (e *APIError) Message() string {
	if e == nil {
		return ""
	}
	return e.message
}
func (e *APIError) Error() string {
	if e == nil {
		return "Open Trestle API error"
	}
	return fmt.Sprintf("Open Trestle API error: status=%d code=%s request_id=%s", e.statusCode, e.code, e.requestID)
}
func (e *APIError) GoString() string { return "client.APIError{<redacted>}" }

type clientErrorRecord struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type clientResponseRecord struct {
	Contract      string             `json:"contract"`
	SchemaVersion int                `json:"schema_version"`
	RequestID     string             `json:"request_id"`
	Run           json.RawMessage    `json:"run,omitempty"`
	Plan          json.RawMessage    `json:"plan,omitempty"`
	Lease         json.RawMessage    `json:"lease,omitempty"`
	Diagnostics   json.RawMessage    `json:"diagnostics,omitempty"`
	Error         *clientErrorRecord `json:"error,omitempty"`
}

func parseClientResponse(encoded []byte) (clientResponseRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record clientResponseRecord
	if err := decoder.Decode(&record); err != nil {
		return clientResponseRecord{}, ErrInvalidResponse
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return clientResponseRecord{}, ErrInvalidResponse
	}
	if record.Contract != "open-trestle/api-response" || record.SchemaVersion != 1 || !validResponseValue(record.RequestID, 128) {
		return clientResponseRecord{}, ErrInvalidResponse
	}
	if record.Error != nil {
		hasSuccess := len(record.Run) != 0 || len(record.Plan) != 0 || len(record.Lease) != 0 || len(record.Diagnostics) != 0
		validError := validResponseValue(record.Error.Code, 64) && validResponseValue(record.Error.Message, 512)
		if hasSuccess || !validError {
			return clientResponseRecord{}, ErrInvalidResponse
		}
	}
	return record, nil
}
func readClientBody(body io.Reader) ([]byte, bool, error) {
	encoded, err := io.ReadAll(io.LimitReader(body, maxClientResponseBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(encoded) > maxClientResponseBytes {
		return nil, true, nil
	}
	return encoded, false, nil
}
func workerPath(scope audit.ReviewScope, taskKey string) string {
	return runPath(scope) + "/tasks/" + url.PathEscape(taskKey)
}
func runPath(scope audit.ReviewScope) string {
	return "/api/v1/tenants/" + url.PathEscape(scope.TenantID()) + "/repositories/" + url.PathEscape(scope.RepositoryID()) + "/runs/" + url.PathEscape(scope.ReviewRunID())
}
func validBaseURL(baseURL *url.URL) bool {
	if baseURL == nil || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" || baseURL.Path != "" && baseURL.Path != "/" || baseURL.Host == "" {
		return false
	}
	if baseURL.Scheme == "https" {
		return true
	}
	if baseURL.Scheme != "http" {
		return false
	}
	address := net.ParseIP(baseURL.Hostname())
	return address != nil && address.IsLoopback()
}
func validClientCredential(value string) bool {
	if len(value) < minClientCredentialBytes || len(value) > maxClientCredentialBytes || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsAny(value, " \t\r\n\x00")
}
func validResponseValue(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
