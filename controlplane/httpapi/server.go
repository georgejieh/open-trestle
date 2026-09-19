// Package httpapi exposes the review-run coordinator through a bounded authenticated HTTP contract.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/apilimit"
	"github.com/georgejieh/open-trestle/runtimeadmin"
)

const (
	maxAPIRequestBodyBytes   = 1 << 20
	maxAPIRequestTargetBytes = 4096
	apiOperationTimeout      = apilimit.OperationTimeout
)

var (
	// ErrInvalidServer identifies missing HTTP API dependencies.
	ErrInvalidServer = errors.New("invalid control-plane HTTP server")
)

// Clock supplies bounded operation timestamps.
type Clock interface{ Now() time.Time }

// SystemClock supplies the current UTC time.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

// DiagnosticReader loads one canonical verified diagnostic set.
type DiagnosticReader interface {
	GetDiagnosticSet(context.Context, audit.ReviewScope) (diagnostics.Set, error)
}

// Server serves the versioned review-run HTTP API.
type Server struct {
	coordinator           *controlplane.Coordinator
	authenticator         Authenticator
	clock                 Clock
	requestLimiter        RateLimiter
	principalLimiter      RateLimiter
	diagnosticReader      DiagnosticReader
	notificationQueue     controlplane.TaskNotificationQueue
	notificationScheduler *controlplane.TaskNotificationScheduler
	runFinalizer          *controlplane.RunFinalizer
	runtimeStatus         RuntimeStatusReader
}

func NewServer(coordinator *controlplane.Coordinator, authenticator Authenticator, clock Clock) (*Server, error) {
	requestLimiter, _ := NewMemoryRateLimiter(apilimit.RequestLimit, apilimit.Window, apilimit.RequestMaximumKeys)
	principalLimiter, _ := NewMemoryRateLimiter(apilimit.PrincipalLimit, apilimit.Window, apilimit.PrincipalMaximumKeys)
	return newServer(coordinator, authenticator, clock, requestLimiter, principalLimiter, nil, nil, nil)
}

// RuntimeStatusReader returns one repository-scoped, content-free runtime snapshot.
type RuntimeStatusReader interface {
	Snapshot(string, string, time.Time) (runtimeadmin.Snapshot, error)
}

// NewServerWithAdministration constructs a server with repository-scoped runtime inspection.
func NewServerWithAdministration(journal controlplane.RunJournal, authenticator Authenticator, clock Clock, status RuntimeStatusReader) (*Server, error) {
	if journal == nil || isNilRuntimeStatusReader(status) {
		return nil, ErrInvalidServer
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		return nil, ErrInvalidServer
	}
	requestLimiter, _ := NewMemoryRateLimiter(apilimit.RequestLimit, apilimit.Window, apilimit.RequestMaximumKeys)
	principalLimiter, _ := NewMemoryRateLimiter(apilimit.PrincipalLimit, apilimit.Window, apilimit.PrincipalMaximumKeys)
	server, err := newServer(coordinator, authenticator, clock, requestLimiter, principalLimiter, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	server.runtimeStatus = status
	return server, nil
}

// NewServerWithRuntimeAdministration adds diagnostics, notifications, and runtime inspection.
func NewServerWithRuntimeAdministration(journal controlplane.RunJournal, authenticator Authenticator, clock Clock, reader DiagnosticReader, queue controlplane.TaskNotificationQueue, status RuntimeStatusReader) (*Server, error) {
	if isNilRuntimeStatusReader(status) {
		return nil, ErrInvalidServer
	}
	server, err := NewServerWithRuntimeServices(journal, authenticator, clock, reader, queue)
	if err != nil {
		return nil, err
	}
	server.runtimeStatus = status
	return server, nil
}

// NewServerWithRuntimeAdministrationAndRateLimiters adds runtime services with explicit shared request guards.
func NewServerWithRuntimeAdministrationAndRateLimiters(journal controlplane.RunJournal, authenticator Authenticator, clock Clock, reader DiagnosticReader, queue controlplane.TaskNotificationQueue, status RuntimeStatusReader, requestLimiter, principalLimiter RateLimiter) (*Server, error) {
	if journal == nil || isNilDiagnosticReader(reader) || isNilNotificationQueue(queue) || isNilRuntimeStatusReader(status) {
		return nil, ErrInvalidServer
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		return nil, ErrInvalidServer
	}
	server, err := newServer(coordinator, authenticator, clock, requestLimiter, principalLimiter, reader, queue, journal)
	if err != nil {
		return nil, err
	}
	server.runtimeStatus = status
	return server, nil
}

// NewServerWithDiagnostics constructs a server with scoped verified diagnostic retrieval.
func NewServerWithDiagnostics(coordinator *controlplane.Coordinator, authenticator Authenticator, clock Clock, reader DiagnosticReader) (*Server, error) {
	if isNilDiagnosticReader(reader) {
		return nil, ErrInvalidServer
	}
	requestLimiter, _ := NewMemoryRateLimiter(apilimit.RequestLimit, apilimit.Window, apilimit.RequestMaximumKeys)
	principalLimiter, _ := NewMemoryRateLimiter(apilimit.PrincipalLimit, apilimit.Window, apilimit.PrincipalMaximumKeys)
	return newServer(coordinator, authenticator, clock, requestLimiter, principalLimiter, reader, nil, nil)
}

// NewServerWithRateLimiters constructs a server with explicit pre-authentication and principal limits.
func NewServerWithRateLimiters(coordinator *controlplane.Coordinator, authenticator Authenticator, clock Clock, requestLimiter, principalLimiter RateLimiter) (*Server, error) {
	return newServer(coordinator, authenticator, clock, requestLimiter, principalLimiter, nil, nil, nil)
}

// NewServerWithRuntimeServices adds scoped diagnostics and durable task notifications.
func NewServerWithRuntimeServices(journal controlplane.RunJournal, authenticator Authenticator, clock Clock, reader DiagnosticReader, queue controlplane.TaskNotificationQueue) (*Server, error) {
	if isNilDiagnosticReader(reader) || isNilNotificationQueue(queue) || journal == nil {
		return nil, ErrInvalidServer
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		return nil, ErrInvalidServer
	}
	requestLimiter, _ := NewMemoryRateLimiter(apilimit.RequestLimit, apilimit.Window, apilimit.RequestMaximumKeys)
	principalLimiter, _ := NewMemoryRateLimiter(apilimit.PrincipalLimit, apilimit.Window, apilimit.PrincipalMaximumKeys)
	return newServer(coordinator, authenticator, clock, requestLimiter, principalLimiter, reader, queue, journal)
}

func newServer(coordinator *controlplane.Coordinator, authenticator Authenticator, clock Clock, requestLimiter, principalLimiter RateLimiter, reader DiagnosticReader, queue controlplane.TaskNotificationQueue, journal controlplane.RunJournal) (*Server, error) {
	if coordinator == nil || authenticator == nil || clock == nil || requestLimiter == nil || principalLimiter == nil {
		return nil, ErrInvalidServer
	}
	server := &Server{coordinator: coordinator, authenticator: authenticator, clock: clock, requestLimiter: requestLimiter, principalLimiter: principalLimiter, diagnosticReader: reader, notificationQueue: queue}
	if !isNilNotificationQueue(queue) {
		scheduler, err := controlplane.NewTaskNotificationScheduler(journal, queue)
		if err != nil {
			return nil, ErrInvalidServer
		}
		server.notificationScheduler = scheduler
		finalizer, err := controlplane.NewRunFinalizer(journal)
		if err != nil {
			return nil, ErrInvalidServer
		}
		server.runFinalizer = finalizer
	}
	return server, nil
}
func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID, err := newRequestID()
	if err != nil {
		requestID = "unavailable"
	}
	setAPIHeaders(writer, requestID)
	if s == nil || s.coordinator == nil || s.authenticator == nil || s.clock == nil || s.requestLimiter == nil || s.principalLimiter == nil || request == nil {
		writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "The request could not be completed.")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), apiOperationTimeout)
	defer cancel()
	at := s.clock.Now()
	allowed, limitErr := s.requestLimiter.Allow(ctx, requestAuthorityKey(request), at)
	if limitErr != nil {
		writeRateLimiterUnavailable(writer, requestID)
		return
	}
	if !allowed {
		writeRateLimited(writer, requestID)
		return
	}
	if len(request.URL.RequestURI()) > maxAPIRequestTargetBytes {
		writeAPIError(writer, http.StatusRequestURITooLong, requestID, "invalid_request", "The request target is too large.")
		return
	}
	principal, authErr := s.authenticate(ctx, request)
	if authErr != nil {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="open-trestle"`)
		writeAPIError(writer, http.StatusUnauthorized, requestID, "unauthenticated", "A valid bearer credential is required.")
		return
	}
	allowed, limitErr = s.principalLimiter.Allow(ctx, principalAuthorityKey(principal), at)
	if limitErr != nil {
		writeRateLimiterUnavailable(writer, requestID)
		return
	}
	if !allowed {
		writeRateLimited(writer, requestID)
		return
	}
	if request.URL.RawQuery != "" {
		writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "Query parameters are not accepted by this endpoint.")
		return
	}
	path := request.URL.EscapedPath()
	statusTenant, statusRepository, statusMatched := parseRuntimeStatusPath(path)
	if statusMatched {
		if request.Method != http.MethodGet {
			writeMethodNotAllowed(writer, requestID, http.MethodGet)
			return
		}
		if principal.TenantID() != statusTenant || !principal.AllowsRepository(statusRepository) || !principal.HasCapability(CapabilityRuntimeRead) {
			writeForbidden(writer, requestID)
			return
		}
		if !requestHasEmptyBody(request) {
			writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "This endpoint does not accept a request body.")
			return
		}
		if isNilRuntimeStatusReader(s.runtimeStatus) {
			writeAPIError(writer, http.StatusNotFound, requestID, "not_found", "Runtime status is not available.")
			return
		}
		snapshot, snapshotErr := s.runtimeStatus.Snapshot(statusTenant, statusRepository, at)
		if snapshotErr != nil {
			writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "Runtime status could not be read.")
			return
		}
		writeRuntimeStatus(writer, http.StatusOK, requestID, snapshot)
		return
	}
	if path == "/api/v1/runs" {
		if request.Method != http.MethodPost {
			writeMethodNotAllowed(writer, requestID, http.MethodPost)
			return
		}
		s.submitRun(ctx, writer, request, requestID, principal, at)
		return
	}
	planScope, planMatched := parseRunActionPath(path, "plan")
	if planMatched {
		if request.Method != http.MethodGet {
			writeMethodNotAllowed(writer, requestID, http.MethodGet)
			return
		}
		allowed := principal.HasCapability(CapabilityRunRead) || principal.HasCapability(CapabilityTaskClaim)
		if !principalAllowsScope(principal, planScope) || !allowed {
			writeForbidden(writer, requestID)
			return
		}
		if !requestHasEmptyBody(request) {
			writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "This endpoint does not accept a request body.")
			return
		}
		plan, _, operationErr := s.coordinator.Resume(ctx, planScope)
		if operationErr != nil {
			s.writeCoordinatorError(writer, requestID, operationErr)
			return
		}
		writeAPIPlan(writer, http.StatusOK, requestID, plan)
		return
	}
	diagnosticScope, diagnosticMatched := parseRunActionPath(path, "diagnostics")
	if diagnosticMatched {
		if request.Method != http.MethodGet {
			writeMethodNotAllowed(writer, requestID, http.MethodGet)
			return
		}
		if !principalAllowsScope(principal, diagnosticScope) || !principal.HasCapability(CapabilityRunRead) {
			writeForbidden(writer, requestID)
			return
		}
		if !requestHasEmptyBody(request) {
			writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "This endpoint does not accept a request body.")
			return
		}
		if isNilDiagnosticReader(s.diagnosticReader) {
			writeAPIError(writer, http.StatusNotFound, requestID, "not_found", "Verified diagnostics are not available.")
			return
		}
		set, readErr := s.diagnosticReader.GetDiagnosticSet(ctx, diagnosticScope)
		if readErr != nil {
			if errors.Is(readErr, diagnostics.ErrSetNotFound) {
				writeAPIError(writer, http.StatusNotFound, requestID, "not_found", "Verified diagnostics were not found.")
			} else {
				writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "Verified diagnostics could not be read.")
			}
			return
		}
		if set.Scope().Identity() != diagnosticScope.Identity() {
			writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "Verified diagnostics could not be read.")
			return
		}
		writeAPIDiagnostics(writer, http.StatusOK, requestID, set)
		return
	}
	finalizeScope, finalizeMatched := parseRunActionPath(path, "finalize")
	if finalizeMatched {
		if request.Method != http.MethodPost {
			writeMethodNotAllowed(writer, requestID, http.MethodPost)
			return
		}
		if !principalAllowsScope(principal, finalizeScope) || !principal.HasCapability(CapabilityRunWrite) {
			writeForbidden(writer, requestID)
			return
		}
		s.finalizeRun(ctx, writer, request, requestID, finalizeScope, at)
		return
	}
	notificationScope, notificationAction, notificationMatched := parseTaskNotificationPath(path)
	if notificationMatched {
		if request.Method != http.MethodPost {
			writeMethodNotAllowed(writer, requestID, http.MethodPost)
			return
		}
		if !principalAllowsScope(principal, notificationScope) || !principal.HasCapability(CapabilityTaskClaim) {
			writeForbidden(writer, requestID)
			return
		}
		s.handleTaskNotificationOperation(ctx, writer, request, requestID, principal, notificationScope, notificationAction, at)
		return
	}
	workerScope, taskKey, workerAction, workerMatched := parseTaskPath(path)
	if workerMatched {
		if request.Method != http.MethodPost {
			writeMethodNotAllowed(writer, requestID, http.MethodPost)
			return
		}
		if !principalAllowsScope(principal, workerScope) {
			writeForbidden(writer, requestID)
			return
		}
		s.handleWorkerOperation(ctx, writer, request, requestID, principal, workerScope, taskKey, workerAction, at)
		return
	}
	scope, cancelRoute, matched := parseRunPath(path)
	if !matched {
		writeAPIError(writer, http.StatusNotFound, requestID, "not_found", "The requested endpoint was not found.")
		return
	}
	if !principalAllowsScope(principal, scope) {
		writeAPIError(writer, http.StatusForbidden, requestID, "forbidden", "The authenticated principal cannot access this scope.")
		return
	}
	if cancelRoute {
		if request.Method != http.MethodPost {
			writeMethodNotAllowed(writer, requestID, http.MethodPost)
			return
		}
		if !principal.HasCapability(CapabilityRunWrite) {
			writeForbidden(writer, requestID)
			return
		}
		if !requestHasEmptyBody(request) {
			writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "This endpoint does not accept a request body.")
			return
		}
		plan, _, operationErr := s.coordinator.Resume(ctx, scope)
		var state controlplane.ReviewRunState
		if operationErr == nil {
			state, operationErr = s.coordinator.CancelRun(ctx, plan, at)
		}
		if operationErr != nil {
			s.writeCoordinatorError(writer, requestID, operationErr)
			return
		}
		receipt, receiptErr := controlplane.NewReviewRunReceipt(state)
		if receiptErr != nil {
			s.writeCoordinatorError(writer, requestID, receiptErr)
			return
		}
		writeAPIReceipt(writer, http.StatusOK, requestID, receipt)
		return
	}
	if request.Method != http.MethodGet {
		writeMethodNotAllowed(writer, requestID, http.MethodGet)
		return
	}
	if !principal.HasCapability(CapabilityRunRead) {
		writeForbidden(writer, requestID)
		return
	}
	if !requestHasEmptyBody(request) {
		writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "This endpoint does not accept a request body.")
		return
	}
	receipt, operationErr := s.coordinator.Receipt(ctx, scope)
	if operationErr != nil {
		s.writeCoordinatorError(writer, requestID, operationErr)
		return
	}
	writeAPIReceipt(writer, http.StatusOK, requestID, receipt)
}
func (s *Server) submitRun(ctx context.Context, writer http.ResponseWriter, request *http.Request, requestID string, principal Principal, at time.Time) {
	if !principal.HasCapability(CapabilityRunWrite) {
		writeForbidden(writer, requestID)
		return
	}
	if request.Header.Get("Content-Encoding") != "" {
		writeAPIError(writer, http.StatusUnsupportedMediaType, requestID, "unsupported_media_type", "Content encoding is not supported.")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAPIError(writer, http.StatusUnsupportedMediaType, requestID, "unsupported_media_type", "Content-Type must be application/json.")
		return
	}
	encoded, tooLarge, readErr := readBoundedBody(request.Body, maxAPIRequestBodyBytes)
	if tooLarge {
		writeAPIError(writer, http.StatusRequestEntityTooLarge, requestID, "request_too_large", "The request body is too large.")
		return
	}
	if readErr != nil {
		writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "The request body could not be read.")
		return
	}
	plan, parseErr := controlplane.ParseReviewRunPlan(encoded)
	if parseErr != nil {
		writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "The review run plan is invalid.")
		return
	}
	if !principalAllowsScope(principal, plan.Scope()) {
		writeForbidden(writer, requestID)
		return
	}
	state, operationErr := s.coordinator.Open(ctx, plan, at)
	if operationErr == nil && s.notificationScheduler != nil {
		state, _, operationErr = s.notificationScheduler.ReconcileRun(ctx, plan.Scope(), at)
	} else if operationErr == nil {
		state, operationErr = s.coordinator.Advance(ctx, plan, at)
	}
	if operationErr != nil {
		s.writeCoordinatorError(writer, requestID, operationErr)
		return
	}
	receipt, receiptErr := controlplane.NewReviewRunReceipt(state)
	if receiptErr != nil {
		s.writeCoordinatorError(writer, requestID, receiptErr)
		return
	}
	writeAPIReceipt(writer, http.StatusAccepted, requestID, receipt)
}
func (s *Server) authenticate(ctx context.Context, request *http.Request) (Principal, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return Principal{}, ErrAuthenticationFailed
	}
	credential := strings.TrimPrefix(values[0], "Bearer ")
	if credential == "" || strings.TrimSpace(credential) != credential {
		return Principal{}, ErrAuthenticationFailed
	}
	return s.authenticator.Authenticate(ctx, credential)
}
func parseRuntimeStatusPath(escapedPath string) (string, string, bool) {
	segments := strings.Split(escapedPath, "/")
	if len(segments) != 8 || segments[0] != "" || segments[1] != "api" || segments[2] != "v1" || segments[3] != "tenants" || segments[5] != "repositories" || segments[7] != "runtime" {
		return "", "", false
	}
	values := make([]string, 2)
	for index, segmentIndex := range []int{4, 6} {
		decoded, err := url.PathUnescape(segments[segmentIndex])
		if err != nil || decoded == "" || strings.Contains(decoded, "/") {
			return "", "", false
		}
		values[index] = decoded
	}
	if _, err := audit.NewReviewScope(values[0], values[1], "runtime-status"); err != nil {
		return "", "", false
	}
	return values[0], values[1], true
}

func parseRunPath(escapedPath string) (audit.ReviewScope, bool, bool) {
	segments := strings.Split(escapedPath, "/")
	cancelRoute := len(segments) == 10 && segments[9] == "cancel"
	if len(segments) != 9 && !cancelRoute {
		return audit.ReviewScope{}, false, false
	}
	if segments[0] != "" || segments[1] != "api" || segments[2] != "v1" || segments[3] != "tenants" || segments[5] != "repositories" || segments[7] != "runs" {
		return audit.ReviewScope{}, false, false
	}
	values := make([]string, 3)
	for index, segmentIndex := range []int{4, 6, 8} {
		decoded, err := url.PathUnescape(segments[segmentIndex])
		if err != nil || decoded == "" || strings.Contains(decoded, "/") {
			return audit.ReviewScope{}, false, false
		}
		values[index] = decoded
	}
	scope, err := audit.NewReviewScope(values[0], values[1], values[2])
	if err != nil {
		return audit.ReviewScope{}, false, false
	}
	return scope, cancelRoute, true
}
func parseRunActionPath(escapedPath, action string) (audit.ReviewScope, bool) {
	suffix := "/" + action
	if !strings.HasSuffix(escapedPath, suffix) {
		return audit.ReviewScope{}, false
	}
	scope, cancelRoute, matched := parseRunPath(strings.TrimSuffix(escapedPath, suffix))
	return scope, matched && !cancelRoute
}
func (s *Server) finalizeRun(ctx context.Context, writer http.ResponseWriter, request *http.Request, requestID string, scope audit.ReviewScope, at time.Time) {
	encoded, status, err := readJSONRequest(request, maxWorkerRequestBytes)
	if err != nil {
		writeAPIError(writer, status, requestID, "invalid_request", "The finalization request is invalid.")
		return
	}
	completion, err := controlplane.ParseTaskCompletion(encoded)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "The finalization request is invalid.")
		return
	}
	plan, _, err := s.coordinator.Resume(ctx, scope)
	if err != nil {
		s.writeCoordinatorError(writer, requestID, err)
		return
	}
	var state controlplane.ReviewRunState
	if completion.Status() == controlplane.TaskCompletionSucceeded {
		state, err = s.coordinator.SucceedRun(ctx, plan, completion.OutputIdentity(), at)
	} else {
		state, err = s.coordinator.FailRun(ctx, plan, completion.Failure(), at)
	}
	if err != nil {
		s.writeCoordinatorError(writer, requestID, err)
		return
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		s.writeCoordinatorError(writer, requestID, err)
		return
	}
	writeAPIReceipt(writer, http.StatusOK, requestID, receipt)
}

func parseTaskNotificationPath(escapedPath string) (audit.ReviewScope, string, bool) {
	segments := strings.Split(escapedPath, "/")
	if len(segments) != 12 || segments[9] != "worker" || segments[10] != "notifications" || (segments[11] != "claim" && segments[11] != "acknowledge") {
		return audit.ReviewScope{}, "", false
	}
	base := strings.Join(segments[:9], "/")
	scope, cancel, matched := parseRunPath(base)
	return scope, segments[11], matched && !cancel
}

func (s *Server) handleTaskNotificationOperation(ctx context.Context, writer http.ResponseWriter, request *http.Request, requestID string, principal Principal, scope audit.ReviewScope, action string, at time.Time) {
	if isNilNotificationQueue(s.notificationQueue) {
		writeAPIError(writer, http.StatusNotFound, requestID, "not_found", "Task notifications are not available.")
		return
	}
	encoded, status, err := readJSONRequest(request, maxWorkerRequestBytes)
	if err != nil {
		writeAPIError(writer, status, requestID, "invalid_request", "The task notification request is invalid.")
		return
	}
	if action == "acknowledge" {
		lease, parseErr := controlplane.ParseTaskNotificationLease(encoded)
		if parseErr != nil || lease.WorkerIdentity() != principal.Identity() || lease.Notification().Scope().Identity() != scope.Identity() {
			writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "The task notification lease is invalid.")
			return
		}
		if err := s.notificationQueue.AcknowledgeTaskNotification(ctx, lease, at); err != nil {
			if errors.Is(err, controlplane.ErrTaskNotificationLeaseMismatch) {
				writeAPIError(writer, http.StatusConflict, requestID, "conflict", "The task notification lease is stale.")
			} else {
				writeAPIError(writer, http.StatusServiceUnavailable, requestID, "unavailable", "Task notifications could not be updated.")
			}
			return
		}
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	wait, leaseDuration, parseErr := parseTaskNotificationClaimRequest(encoded)
	if parseErr != nil {
		writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "The task notification claim is invalid.")
		return
	}
	lease, found, claimErr := s.notificationQueue.ClaimTaskNotification(ctx, scope, principal.Identity(), at, leaseDuration)
	if claimErr != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, requestID, "unavailable", "Task notifications could not be read.")
		return
	}
	if !found && wait > 0 {
		if waiter, ok := s.notificationQueue.(controlplane.TaskNotificationWaiter); ok && !isNilTaskNotificationWaiter(waiter) {
			waitContext, cancel := context.WithTimeout(ctx, wait)
			waitErr := waiter.WaitForTaskNotification(waitContext)
			waitState := waitContext.Err()
			cancel()
			if waitErr != nil && waitState == nil && !errors.Is(waitErr, controlplane.ErrTaskNotificationWaitCanceled) {
				writeAPIError(writer, http.StatusServiceUnavailable, requestID, "unavailable", "Task notifications could not be read.")
				return
			}
			if ctx.Err() == nil {
				lease, found, claimErr = s.notificationQueue.ClaimTaskNotification(ctx, scope, principal.Identity(), s.clock.Now().UTC(), leaseDuration)
			}
		}
	}
	if claimErr != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, requestID, "unavailable", "Task notifications could not be read.")
		return
	}
	if !found {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	writeAPITaskNotificationLease(writer, http.StatusOK, requestID, lease)
}
func isNilTaskNotificationWaiter(waiter controlplane.TaskNotificationWaiter) bool {
	if waiter == nil {
		return true
	}
	value := reflect.ValueOf(waiter)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

func parseTaskPath(escapedPath string) (audit.ReviewScope, string, string, bool) {
	segments := strings.Split(escapedPath, "/")
	validLength := len(segments) == 12
	validLabels := validLength && segments[0] == "" && segments[1] == "api" && segments[2] == "v1" &&
		segments[3] == "tenants" && segments[5] == "repositories" && segments[7] == "runs" && segments[9] == "tasks"
	if !validLabels {
		return audit.ReviewScope{}, "", "", false
	}
	values := make([]string, 4)
	for index, segmentIndex := range []int{4, 6, 8, 10} {
		decoded, err := url.PathUnescape(segments[segmentIndex])
		if err != nil || decoded == "" || strings.Contains(decoded, "/") {
			return audit.ReviewScope{}, "", "", false
		}
		values[index] = decoded
	}
	action := segments[11]
	if action != "claim" && action != "renew" && action != "complete" {
		return audit.ReviewScope{}, "", "", false
	}
	scope, err := audit.NewReviewScope(values[0], values[1], values[2])
	if err != nil {
		return audit.ReviewScope{}, "", "", false
	}
	return scope, values[3], action, true
}
func (s *Server) handleWorkerOperation(
	ctx context.Context,
	writer http.ResponseWriter,
	request *http.Request,
	requestID string,
	principal Principal,
	scope audit.ReviewScope,
	taskKey string,
	action string,
	at time.Time,
) {
	capability := CapabilityTaskClaim
	if action == "complete" {
		capability = CapabilityTaskComplete
	}
	if !principal.HasCapability(capability) {
		writeForbidden(writer, requestID)
		return
	}
	encoded, status, err := readJSONRequest(request, maxWorkerRequestBytes)
	if err != nil {
		writeAPIError(writer, status, requestID, "invalid_request", "The worker request is invalid.")
		return
	}
	plan, _, err := s.coordinator.Resume(ctx, scope)
	if err != nil {
		s.writeCoordinatorError(writer, requestID, err)
		return
	}
	if _, exists := plan.Task(taskKey); !exists {
		writeAPIError(writer, http.StatusNotFound, requestID, "not_found", "The review task was not found.")
		return
	}
	switch action {
	case "claim":
		handlerIdentity, parseErr := parseTaskClaimRequest(encoded)
		if parseErr != nil {
			writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "The task claim is invalid.")
			return
		}
		lease, acquired, claimErr := s.coordinator.ClaimTask(ctx, plan, taskKey, handlerIdentity, principal.Identity(), at)
		if claimErr != nil {
			s.writeCoordinatorError(writer, requestID, claimErr)
			return
		}
		if !acquired {
			writeAPIError(writer, http.StatusConflict, requestID, "conflict", "The review task is not claimable.")
			return
		}
		writeAPILease(writer, http.StatusOK, requestID, lease)
	case "renew":
		lease, parseErr := controlplane.ParseTaskLease(encoded)
		if parseErr != nil || lease.TaskKey() != taskKey || lease.WorkerIdentity() != principal.Identity() {
			writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "The task lease is invalid.")
			return
		}
		renewed, _, renewErr := s.coordinator.RenewTaskLease(ctx, plan, lease, at)
		if renewErr != nil {
			s.writeCoordinatorError(writer, requestID, renewErr)
			return
		}
		writeAPILease(writer, http.StatusOK, requestID, renewed)
	case "complete":
		lease, completion, parseErr := parseTaskCompletionRequest(encoded)
		if parseErr != nil || lease.TaskKey() != taskKey || lease.WorkerIdentity() != principal.Identity() {
			writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "The task completion is invalid.")
			return
		}
		state, completionErr := s.coordinator.CompleteTask(ctx, plan, lease, completion, at)
		if completionErr == nil && s.notificationScheduler != nil {
			state, _, completionErr = s.notificationScheduler.ReconcileRun(ctx, plan.Scope(), at)
		} else if completionErr == nil {
			state, completionErr = s.coordinator.Advance(ctx, plan, at)
		}
		if completionErr == nil && s.runFinalizer != nil {
			state, _, completionErr = s.runFinalizer.ReconcileRun(ctx, scope, at)
		}
		if completionErr != nil {
			s.writeCoordinatorError(writer, requestID, completionErr)
			return
		}
		receipt, receiptErr := controlplane.NewReviewRunReceipt(state)
		if receiptErr != nil {
			s.writeCoordinatorError(writer, requestID, receiptErr)
			return
		}
		writeAPIReceipt(writer, http.StatusOK, requestID, receipt)
	}
}
func readJSONRequest(request *http.Request, limit int64) ([]byte, int, error) {
	if request.Header.Get("Content-Encoding") != "" {
		return nil, http.StatusUnsupportedMediaType, ErrInvalidWorkerRequest
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, http.StatusUnsupportedMediaType, ErrInvalidWorkerRequest
	}
	encoded, tooLarge, err := readBoundedBody(request.Body, limit)
	if tooLarge {
		return nil, http.StatusRequestEntityTooLarge, ErrInvalidWorkerRequest
	}
	if err != nil {
		return nil, http.StatusBadRequest, ErrInvalidWorkerRequest
	}
	return encoded, 0, nil
}

func principalAllowsScope(principal Principal, scope audit.ReviewScope) bool {
	return principal.TenantID() == scope.TenantID() && principal.AllowsRepository(scope.RepositoryID())
}
func readBoundedBody(body io.ReadCloser, limit int64) ([]byte, bool, error) {
	if body == nil {
		return nil, false, nil
	}
	defer body.Close()
	encoded, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(encoded)) > limit {
		return nil, true, nil
	}
	return encoded, false, nil
}
func requestHasEmptyBody(request *http.Request) bool {
	if request.Body == nil || request.Body == http.NoBody {
		return true
	}
	encoded, tooLarge, err := readBoundedBody(request.Body, 0)
	return err == nil && !tooLarge && len(encoded) == 0
}
func newRequestID() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
func isNilNotificationQueue(queue controlplane.TaskNotificationQueue) bool {
	if queue == nil {
		return true
	}
	value := reflect.ValueOf(queue)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

func isNilDiagnosticReader(reader DiagnosticReader) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	return value.Kind() == reflect.Ptr && value.IsNil()
}

func requestAuthorityKey(request *http.Request) string {
	return apilimit.RequestAuthorityKey(request.RemoteAddr)
}
func principalAuthorityKey(principal Principal) string {
	return apilimit.PrincipalAuthorityKey(principal.TenantID(), principal.Identity())
}
func writeRateLimiterUnavailable(writer http.ResponseWriter, requestID string) {
	writer.Header().Set("Retry-After", strconv.Itoa(apilimit.UnavailableRetryAfterSeconds))
	writeAPIError(writer, apilimit.UnavailableHTTPStatus, requestID, apilimit.UnavailableErrorCode, "The shared request guard is unavailable.")
}

func writeRateLimited(writer http.ResponseWriter, requestID string) {
	writer.Header().Set("Retry-After", strconv.Itoa(apilimit.DeniedRetryAfterSeconds))
	writeAPIError(writer, apilimit.DeniedHTTPStatus, requestID, apilimit.DeniedErrorCode, "The request rate limit was exceeded.")
}

func setAPIHeaders(writer http.ResponseWriter, requestID string) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Request-ID", requestID)
}

type apiErrorRecord struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type apiResponseRecord struct {
	Contract      string          `json:"contract"`
	SchemaVersion int             `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	Run           json.RawMessage `json:"run,omitempty"`
	Plan          json.RawMessage `json:"plan,omitempty"`
	Lease         json.RawMessage `json:"lease,omitempty"`
	Diagnostics   json.RawMessage `json:"diagnostics,omitempty"`
	Error         *apiErrorRecord `json:"error,omitempty"`
}

type runtimeStatusResponse struct {
	Contract      string          `json:"contract"`
	SchemaVersion int             `json:"schema_version"`
	RequestID     string          `json:"request_id"`
	Status        json.RawMessage `json:"status"`
}

func writeRuntimeStatus(writer http.ResponseWriter, status int, requestID string, snapshot runtimeadmin.Snapshot) {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "Runtime status could not be read.")
		return
	}
	payload, err := json.Marshal(runtimeStatusResponse{Contract: "open-trestle/runtime-status-response", SchemaVersion: 1, RequestID: requestID, Status: encoded})
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "Runtime status could not be read.")
		return
	}
	writer.WriteHeader(status)
	_, _ = writer.Write(payload)
}

func writeAPIPlan(writer http.ResponseWriter, status int, requestID string, plan controlplane.ReviewRunPlan) {
	encoded, err := controlplane.EncodeReviewRunPlan(plan)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "The request could not be completed.")
		return
	}
	writeAPIJSON(writer, status, apiResponseRecord{Contract: "open-trestle/api-response", SchemaVersion: 1, RequestID: requestID, Plan: json.RawMessage(encoded)})
}

func writeAPIReceipt(writer http.ResponseWriter, status int, requestID string, receipt controlplane.ReviewRunReceipt) {
	encoded, err := controlplane.EncodeReviewRunReceipt(receipt)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "The request could not be completed.")
		return
	}
	writeAPIJSON(writer, status, apiResponseRecord{Contract: "open-trestle/api-response", SchemaVersion: 1, RequestID: requestID, Run: json.RawMessage(encoded)})
}
func writeAPIDiagnostics(writer http.ResponseWriter, status int, requestID string, set diagnostics.Set) {
	encoded, err := diagnostics.EncodeSet(set)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "The request could not be completed.")
		return
	}
	writeAPIJSON(writer, status, apiResponseRecord{Contract: "open-trestle/api-response", SchemaVersion: 1, RequestID: requestID, Diagnostics: json.RawMessage(encoded)})
}

func writeAPILease(writer http.ResponseWriter, status int, requestID string, lease controlplane.TaskLease) {
	encoded, err := controlplane.EncodeTaskLease(lease)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "The request could not be completed.")
		return
	}
	writeAPIJSON(writer, status, apiResponseRecord{Contract: "open-trestle/api-response", SchemaVersion: 1, RequestID: requestID, Lease: json.RawMessage(encoded)})
}

func writeAPITaskNotificationLease(writer http.ResponseWriter, status int, requestID string, lease controlplane.TaskNotificationLease) {
	encoded, err := controlplane.EncodeTaskNotificationLease(lease)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "The request could not be completed.")
		return
	}
	writeAPIJSON(writer, status, apiResponseRecord{Contract: "open-trestle/api-response", SchemaVersion: 1, RequestID: requestID, Lease: json.RawMessage(encoded)})
}

func writeAPIError(writer http.ResponseWriter, status int, requestID, code, message string) {
	writeAPIJSON(writer, status, apiResponseRecord{Contract: "open-trestle/api-response", SchemaVersion: 1, RequestID: requestID, Error: &apiErrorRecord{Code: code, Message: message}})
}
func writeAPIJSON(writer http.ResponseWriter, status int, response apiResponseRecord) {
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > apilimit.MaximumResponseBytes {
		http.Error(writer, "internal error", http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}
func writeMethodNotAllowed(writer http.ResponseWriter, requestID, allowed string) {
	writer.Header().Set("Allow", allowed)
	writeAPIError(writer, http.StatusMethodNotAllowed, requestID, "method_not_allowed", "The request method is not allowed.")
}
func writeForbidden(writer http.ResponseWriter, requestID string) {
	writeAPIError(writer, http.StatusForbidden, requestID, "forbidden", "The authenticated principal does not have this authority.")
}
func isCoordinatorConflict(err error) bool {
	return errors.Is(err, controlplane.ErrRunPlanConflict) ||
		errors.Is(err, controlplane.ErrRunJournalHeadConflict) ||
		errors.Is(err, controlplane.ErrCoordinatorContention) ||
		errors.Is(err, controlplane.ErrRunTransitionLeaseMismatch) ||
		errors.Is(err, controlplane.ErrRunTransitionInvalid) ||
		errors.Is(err, controlplane.ErrRunTransitionDependencyBlocked) ||
		errors.Is(err, controlplane.ErrRunTransitionSequenceMismatch) ||
		errors.Is(err, controlplane.ErrRunTransitionAttemptLimit) ||
		errors.Is(err, controlplane.ErrInvalidReviewTaskHandler) ||
		errors.Is(err, controlplane.ErrRunAlreadyTerminal) ||
		errors.Is(err, controlplane.ErrTaskAlreadyCompleted)
}

func (s *Server) writeCoordinatorError(writer http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, controlplane.ErrTaskLeaseRenewalLimit):
		writeAPIError(writer, http.StatusConflict, requestID, "lease_renewal_limit", "The task cannot extend its lease within the run event budget.")
	case errors.Is(err, controlplane.ErrRunNotOpened):
		writeAPIError(writer, http.StatusNotFound, requestID, "not_found", "The review run was not found.")
	case errors.Is(err, controlplane.ErrReviewTaskNotFound):
		writeAPIError(writer, http.StatusNotFound, requestID, "not_found", "The review task was not found.")
	case isCoordinatorConflict(err):
		writeAPIError(writer, http.StatusConflict, requestID, "conflict", "The review run changed or conflicts with this request.")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, controlplane.ErrRunJournalContextDone):
		writeAPIError(writer, http.StatusServiceUnavailable, requestID, "unavailable", "The operation did not complete.")
	default:
		writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "The request could not be completed.")
	}
}

func isNilRuntimeStatusReader(reader RuntimeStatusReader) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}
