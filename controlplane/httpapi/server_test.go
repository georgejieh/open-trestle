package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
)

const testAPIToken = "01234567890123456789012345678901"

type fixedClock struct{ at time.Time }

func (c fixedClock) Now() time.Time { return c.at }
func apiPlan(t *testing.T) controlplane.ReviewRunPlan {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	specs := []struct {
		key          string
		kind         controlplane.TaskKind
		dependencies []string
		attempts     uint8
	}{{"source", controlplane.TaskAcquireSource, nil, 3}, {"change", controlplane.TaskBuildChange, []string{"source"}, 3}, {"analysis", controlplane.TaskInspectDeterministic, []string{"change"}, 3}, {"memory", controlplane.TaskRetrieveContext, []string{"change"}, 3}, {"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}, 3}, {"candidates", controlplane.TaskGenerateCandidates, []string{"context"}, 3}, {"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}, 3}, {"readiness", controlplane.TaskEvaluatePublication, []string{"analysis", "change", "verification"}, 3}, {"publication", controlplane.TaskPublishResult, []string{"readiness"}, 1}}
	tasks := make([]controlplane.TaskDefinition, 0, len(specs))
	for _, spec := range specs {
		task, taskErr := controlplane.NewTaskDefinition(spec.key, spec.kind, strings.Repeat("a", 64), strings.Repeat("d", 64), spec.dependencies, spec.attempts, 1000, 30000, true)
		if taskErr != nil {
			t.Fatal(taskErr)
		}
		tasks = append(tasks, task)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunRequired, tasks)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
func apiServer(t *testing.T) (*Server, controlplane.ReviewRunPlan) {
	t.Helper()
	principal, err := NewPrincipal("operator-1", "tenant-a", []string{"repo-a"}, []Capability{CapabilityRunRead, CapabilityRunWrite})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(coordinator, authenticator, fixedClock{at: time.UnixMilli(1000)})
	if err != nil {
		t.Fatal(err)
	}
	return server, apiPlan(t)
}
func authenticatedRequest(method, target string, body []byte) *http.Request {
	request := httptest.NewRequest(method, target, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testAPIToken)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request
}
func TestServerSubmitsObservesAndCancelsRun(t *testing.T) {
	server, plan := apiServer(t)
	encodedPlan, err := controlplane.EncodeReviewRunPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	submit := httptest.NewRecorder()
	server.ServeHTTP(submit, authenticatedRequest(http.MethodPost, "https://trestle.test/api/v1/runs", encodedPlan))
	if submit.Code != http.StatusAccepted {
		t.Fatalf("submit status=%d body=%s", submit.Code, submit.Body.String())
	}
	submitted := decodeAPIReceipt(t, submit.Body.Bytes())
	if submitted.PlanIdentity() != plan.Identity() || submitted.Status() != controlplane.ReviewRunActive {
		t.Fatalf("submitted=%#v", submitted)
	}
	status := httptest.NewRecorder()
	server.ServeHTTP(status, authenticatedRequest(http.MethodGet, "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a", nil))
	if status.Code != http.StatusOK || decodeAPIReceipt(t, status.Body.Bytes()).Identity() != submitted.Identity() {
		t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
	}
	cancel := httptest.NewRecorder()
	server.ServeHTTP(cancel, authenticatedRequest(http.MethodPost, "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/cancel", nil))
	if cancel.Code != http.StatusOK || decodeAPIReceipt(t, cancel.Body.Bytes()).Status() != controlplane.ReviewRunCanceled {
		t.Fatalf("cancel=%d body=%s", cancel.Code, cancel.Body.String())
	}
}
func TestServerRejectsAuthenticationScopeAndMalformedInput(t *testing.T) {
	server, plan := apiServer(t)
	encodedPlan, _ := controlplane.EncodeReviewRunPlan(plan)
	tests := []struct {
		name    string
		request *http.Request
		status  int
		code    string
	}{{"missing auth", httptest.NewRequest(http.MethodPost, "https://trestle.test/api/v1/runs", bytes.NewReader(encodedPlan)), http.StatusUnauthorized, "unauthenticated"}, {"wrong scheme", func() *http.Request {
		r := authenticatedRequest(http.MethodPost, "https://trestle.test/api/v1/runs", encodedPlan)
		r.Header.Set("Authorization", "Basic "+testAPIToken)
		return r
	}(), http.StatusUnauthorized, "unauthenticated"}, {"cross tenant", authenticatedRequest(http.MethodGet, "https://trestle.test/api/v1/tenants/tenant-b/repositories/repo-a/runs/run-a", nil), http.StatusForbidden, "forbidden"}, {"cross repository", authenticatedRequest(http.MethodGet, "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-b/runs/run-a", nil), http.StatusForbidden, "forbidden"}, {"unknown plan field", authenticatedRequest(http.MethodPost, "https://trestle.test/api/v1/runs", append(encodedPlan[:len(encodedPlan)-1], []byte(`,"extra":true}`)...)), http.StatusBadRequest, "invalid_request"}, {"query parameter", authenticatedRequest(http.MethodGet, "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a?token=secret", nil), http.StatusBadRequest, "invalid_request"}, {"cancel body", authenticatedRequest(http.MethodPost, "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/cancel", []byte(`{}`)), http.StatusBadRequest, "invalid_request"}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.ServeHTTP(response, test.request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			apiError := decodeAPIError(t, response.Body.Bytes())
			if apiError.Code != test.code {
				t.Fatalf("error=%#v", apiError)
			}
			if strings.Contains(response.Body.String(), testAPIToken) {
				t.Fatal("response leaked token")
			}
		})
	}
}
func TestServerBoundsBodiesAndMethods(t *testing.T) {
	server, _ := apiServer(t)
	oversized := bytes.Repeat([]byte("x"), maxAPIRequestBodyBytes+1)
	tests := []struct {
		name    string
		request *http.Request
		status  int
	}{{"oversized", authenticatedRequest(http.MethodPost, "https://trestle.test/api/v1/runs", oversized), http.StatusRequestEntityTooLarge}, {"media type", func() *http.Request {
		r := authenticatedRequest(http.MethodPost, "https://trestle.test/api/v1/runs", []byte("{}"))
		r.Header.Set("Content-Type", "text/plain")
		return r
	}(), http.StatusUnsupportedMediaType}, {"method", authenticatedRequest(http.MethodDelete, "https://trestle.test/api/v1/runs", nil), http.StatusMethodNotAllowed}, {"unknown", authenticatedRequest(http.MethodGet, "https://trestle.test/api/v1/unknown", nil), http.StatusNotFound}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			server.ServeHTTP(response, test.request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("X-Request-ID") == "" {
				t.Fatalf("security headers=%v", response.Header())
			}
		})
	}
}

type apiResponseForTest struct {
	Contract      string          `json:"contract"`
	SchemaVersion int             `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	Run           json.RawMessage `json:"run"`
	Error         *apiErrorRecord `json:"error"`
}

func decodeAPIReceipt(t *testing.T, body []byte) controlplane.ReviewRunReceipt {
	t.Helper()
	var response apiResponseForTest
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if response.Contract != "open-trestle/api-response" || response.SchemaVersion != 1 || response.RequestID == "" || response.Error != nil {
		t.Fatalf("response=%#v", response)
	}
	receipt, err := controlplane.ParseReviewRunReceipt(response.Run)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
func decodeAPIError(t *testing.T, body []byte) apiErrorRecord {
	t.Helper()
	var response apiResponseForTest
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if response.Error == nil || len(response.Run) != 0 {
		t.Fatalf("response=%#v", response)
	}
	return *response.Error
}
func TestNewServerRejectsMissingDependencies(t *testing.T) {
	principal, _ := NewPrincipal("operator-1", "tenant-a", []string{"repo-a"}, []Capability{CapabilityRunRead})
	authenticator, _ := NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	tests := []struct {
		name          string
		coordinator   *controlplane.Coordinator
		authenticator Authenticator
		clock         Clock
	}{{"coordinator", nil, authenticator, fixedClock{}}, {"authenticator", coordinator, nil, fixedClock{}}, {"clock", coordinator, authenticator, nil}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, err := NewServer(test.coordinator, test.authenticator, test.clock)
			if !errors.Is(err, ErrInvalidServer) || server != nil {
				t.Fatalf("server=(%#v,%v)", server, err)
			}
		})
	}
}

func TestServerRateLimitsAuthenticatedPrincipal(t *testing.T) {
	principal, _ := NewPrincipal("operator-1", "tenant-a", []string{"repo-a"}, []Capability{CapabilityRunRead})
	authenticator, _ := NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	requestLimiter, _ := NewMemoryRateLimiter(10, time.Minute, 10)
	principalLimiter, _ := NewMemoryRateLimiter(1, time.Minute, 10)
	server, err := NewServerWithRateLimiters(coordinator, authenticator, fixedClock{at: time.Unix(1000, 0)}, requestLimiter, principalLimiter)
	if err != nil {
		t.Fatal(err)
	}
	target := "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/missing"
	first := httptest.NewRecorder()
	server.ServeHTTP(first, authenticatedRequest(http.MethodGet, target, nil))
	if first.Code != http.StatusNotFound {
		t.Fatalf("first=%d", first.Code)
	}
	second := httptest.NewRecorder()
	server.ServeHTTP(second, authenticatedRequest(http.MethodGet, target, nil))
	if second.Code != http.StatusTooManyRequests || decodeAPIError(t, second.Body.Bytes()).Code != "rate_limited" || second.Header().Get("Retry-After") == "" {
		t.Fatalf("second=%d body=%s", second.Code, second.Body.String())
	}
}

type mutableClock struct{ at time.Time }

func (c *mutableClock) Now() time.Time { return c.at }
func TestServerClaimsRenewsAndCompletesWorkerTask(t *testing.T) {
	principal, _ := NewPrincipal("worker-1", "tenant-a", []string{"repo-a"}, []Capability{CapabilityRunWrite, CapabilityTaskClaim, CapabilityTaskComplete})
	authenticator, _ := NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	clock := &mutableClock{at: time.UnixMilli(1000)}
	server, err := NewServer(coordinator, authenticator, clock)
	if err != nil {
		t.Fatal(err)
	}
	plan := apiPlan(t)
	encodedPlan, _ := controlplane.EncodeReviewRunPlan(plan)
	submit := httptest.NewRecorder()
	server.ServeHTTP(submit, authenticatedRequest(http.MethodPost, "https://trestle.test/api/v1/runs", encodedPlan))
	if submit.Code != http.StatusAccepted {
		t.Fatalf("submit=%d %s", submit.Code, submit.Body.String())
	}
	claimBody, _ := json.Marshal(taskClaimRequestRecord{Contract: "open-trestle/task-claim-request", SchemaVersion: 1, HandlerIdentity: strings.Repeat("d", 64)})
	taskURL := "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/tasks/source"
	claim := httptest.NewRecorder()
	server.ServeHTTP(claim, authenticatedRequest(http.MethodPost, taskURL+"/claim", claimBody))
	lease := decodeAPILease(t, claim)
	if lease.WorkerIdentity() != "worker-1" || lease.TaskKey() != "source" {
		t.Fatalf("lease=%#v", lease)
	}
	duplicateClaim := httptest.NewRecorder()
	server.ServeHTTP(duplicateClaim, authenticatedRequest(http.MethodPost, taskURL+"/claim", claimBody))
	if duplicateClaim.Code != http.StatusConflict {
		t.Fatalf("duplicate claim=%d %s", duplicateClaim.Code, duplicateClaim.Body.String())
	}
	clock.at = time.UnixMilli(1001)
	encodedLease, _ := controlplane.EncodeTaskLease(lease)
	renew := httptest.NewRecorder()
	server.ServeHTTP(renew, authenticatedRequest(http.MethodPost, taskURL+"/renew", encodedLease))
	renewed := decodeAPILease(t, renew)
	if !renewed.ExpiresAt().After(lease.ExpiresAt()) {
		t.Fatalf("renewed=%#v", renewed)
	}
	completion, _ := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
	encodedCompletion, _ := controlplane.EncodeTaskCompletion(completion)
	encodedRenewed, _ := controlplane.EncodeTaskLease(renewed)
	completionBody, _ := json.Marshal(taskCompletionRequestRecord{Contract: "open-trestle/task-completion-request", SchemaVersion: 1, Lease: encodedRenewed, Completion: encodedCompletion})
	clock.at = time.UnixMilli(1002)
	complete := httptest.NewRecorder()
	server.ServeHTTP(complete, authenticatedRequest(http.MethodPost, taskURL+"/complete", completionBody))
	if complete.Code != http.StatusOK {
		t.Fatalf("complete=%d %s", complete.Code, complete.Body.String())
	}
	receipt := decodeAPIReceipt(t, complete.Body.Bytes())
	source, found := receipt.Task("source")
	change, changeFound := receipt.Task("change")
	if !found || source.Status() != controlplane.TaskRuntimeSucceeded || !changeFound || change.Status() != controlplane.TaskRuntimeAvailable {
		t.Fatalf("tasks=(%#v,%#v)", source, change)
	}
	staleBody, _ := json.Marshal(taskCompletionRequestRecord{Contract: "open-trestle/task-completion-request", SchemaVersion: 1, Lease: encodedLease, Completion: encodedCompletion})
	stale := httptest.NewRecorder()
	server.ServeHTTP(stale, authenticatedRequest(http.MethodPost, taskURL+"/complete", staleBody))
	if stale.Code != http.StatusOK || strings.Contains(stale.Body.String(), string(encodedLease)) {
		t.Fatalf("idempotent completion=%d %s", stale.Code, stale.Body.String())
	}
}
func decodeAPILease(t *testing.T, response *httptest.ResponseRecorder) controlplane.TaskLease {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("lease status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Contract      string          `json:"contract"`
		SchemaVersion int             `json:"schema_version"`
		RequestID     string          `json:"request_id"`
		Lease         json.RawMessage `json:"lease"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	lease, err := controlplane.ParseTaskLease(envelope.Lease)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func TestServerReturnsScopedVerifiedDiagnostics(t *testing.T) {
	principal, _ := NewPrincipal("operator-1", "tenant-a", []string{"repo-a"}, []Capability{CapabilityRunRead})
	authenticator, _ := NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	omission, _ := diagnostics.NewOmissionSummary(diagnostics.OmissionSelectionLimit, 172)
	set, _ := diagnostics.NewSetWithOmissionReasons(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64), 2, 1, 1, 173, 1, 172, []diagnostics.OmissionSummary{omission}, nil)
	store := diagnostics.NewMemoryStore()
	_, _ = store.PutDiagnosticSet(context.Background(), set)
	server, err := NewServerWithDiagnostics(coordinator, authenticator, fixedClock{at: time.UnixMilli(1000)}, store)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, authenticatedRequest(http.MethodGet, "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/diagnostics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
	var envelope struct {
		Diagnostics json.RawMessage `json:"diagnostics"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	parsed, err := diagnostics.ParseSet(envelope.Diagnostics)
	if err != nil || parsed.Identity() != set.Identity() || parsed.SchemaVersion() != 4 || len(parsed.OmissionSummaries()) != 1 || parsed.OmissionSummaries()[0].Count() != 172 || parsed.CandidateCount() != 2 || parsed.RejectedCount() != 1 || parsed.InconclusiveCount() != 1 || parsed.SourceAnalyzedCount() != 173 || parsed.SourceSelectedCount() != 1 || parsed.SourceOmittedCount() != 172 {
		t.Fatalf("set=(%#v,%v)", parsed, err)
	}
}

func TestServerReturnsExactRunPlanForAuthorizedWorker(t *testing.T) {
	server, plan := apiServer(t)
	encoded, _ := controlplane.EncodeReviewRunPlan(plan)
	submit := httptest.NewRecorder()
	server.ServeHTTP(submit, authenticatedRequest(http.MethodPost, "https://trestle.test/api/v1/runs", encoded))
	target := "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/run-a/plan"
	response := httptest.NewRecorder()
	server.ServeHTTP(response, authenticatedRequest(http.MethodGet, target, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope apiResponseRecord
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	parsed, err := controlplane.ParseReviewRunPlan(envelope.Plan)
	if err != nil || parsed.Identity() != plan.Identity() {
		t.Fatalf("plan=(%#v,%v)", parsed, err)
	}
}

type unavailableRateLimiter struct{}

func (unavailableRateLimiter) Allow(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("unavailable")
}
func TestServerFailsClosedWhenRateLimiterIsUnavailable(t *testing.T) {
	principal, _ := NewPrincipal("operator-1", "tenant-a", []string{"repo-a"}, []Capability{CapabilityRunRead})
	authenticator, _ := NewStaticTokenAuthenticator([]StaticToken{{Token: testAPIToken, Principal: principal}})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	principalLimiter, _ := NewMemoryRateLimiter(10, time.Minute, 10)
	server, err := NewServerWithRateLimiters(coordinator, authenticator, fixedClock{at: time.Unix(1000, 0)}, unavailableRateLimiter{}, principalLimiter)
	if err != nil {
		t.Fatal(err)
	}
	target := "https://trestle.test/api/v1/tenants/tenant-a/repositories/repo-a/runs/missing"
	response := httptest.NewRecorder()
	server.ServeHTTP(response, authenticatedRequest(http.MethodGet, target, nil))
	if response.Code != http.StatusServiceUnavailable || decodeAPIError(t, response.Body.Bytes()).Code != "rate_limit_unavailable" {
		t.Fatalf("request limiter=%d %s", response.Code, response.Body.String())
	}
	requestLimiter, _ := NewMemoryRateLimiter(10, time.Minute, 10)
	server, err = NewServerWithRateLimiters(coordinator, authenticator, fixedClock{at: time.Unix(1000, 0)}, requestLimiter, unavailableRateLimiter{})
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	server.ServeHTTP(response, authenticatedRequest(http.MethodGet, target, nil))
	if response.Code != http.StatusServiceUnavailable || decodeAPIError(t, response.Body.Bytes()).Code != "rate_limit_unavailable" {
		t.Fatalf("principal limiter=%d %s", response.Code, response.Body.String())
	}
}
