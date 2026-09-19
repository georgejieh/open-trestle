package github

import (
	"encoding/json"
	"errors"
	"github.com/georgejieh/open-trestle/webhook"
	"io"
	"mime"
	"net/http"
	"time"
)

const (
	maxHTTPWebhookBodyBytes = 1 << 20
	maxWebhookHeaderBytes   = 256
	maxWebhookConcurrency   = 1024
)

var ErrInvalidHTTPHandler = errors.New("invalid GitHub webhook HTTP handler")

type Clock interface{ Now() time.Time }

// SystemClock supplies the current UTC time.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

// HTTPHandler verifies and durably stores GitHub deliveries before acknowledging them.
type HTTPHandler struct {
	scope    webhook.RepositoryScope
	verifier *Verifier
	inbox    *webhook.Inbox
	clock    Clock
	notifier webhook.DeliveryNotifier
	slots    chan struct{}
}

func NewHTTPHandler(scope webhook.RepositoryScope, verifier *Verifier, inbox *webhook.Inbox, clock Clock, concurrency uint16) (*HTTPHandler, error) {
	return NewHTTPHandlerWithNotifier(scope, verifier, inbox, nil, clock, concurrency)
}

// NewHTTPHandlerWithNotifier adds a best-effort content-free wake-up after durable acceptance.
func NewHTTPHandlerWithNotifier(scope webhook.RepositoryScope, verifier *Verifier, inbox *webhook.Inbox, notifier webhook.DeliveryNotifier, clock Clock, concurrency uint16) (*HTTPHandler, error) {
	if scope.Validate() != nil || verifier == nil || inbox == nil || clock == nil || concurrency == 0 || concurrency > maxWebhookConcurrency {
		return nil, ErrInvalidHTTPHandler
	}
	return &HTTPHandler{scope: scope, verifier: verifier, inbox: inbox, notifier: notifier, clock: clock, slots: make(chan struct{}, concurrency)}, nil
}
func (h *HTTPHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setWebhookHeaders(writer)
	if h == nil || h.verifier == nil || h.inbox == nil || h.clock == nil || request == nil {
		writeWebhookError(writer, http.StatusInternalServerError, "internal_error")
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		writeWebhookError(writer, http.StatusServiceUnavailable, "busy")
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		writeWebhookError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if request.URL.Path != "/webhooks/github" || request.URL.RawQuery != "" {
		writeWebhookError(writer, http.StatusNotFound, "not_found")
		return
	}
	if request.Header.Get("Content-Encoding") != "" {
		writeWebhookError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeWebhookError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	deliveryID, ok := exactWebhookHeader(request, "X-GitHub-Delivery")
	if !ok {
		writeWebhookError(writer, http.StatusBadRequest, "invalid_headers")
		return
	}
	eventType, ok := exactWebhookHeader(request, "X-GitHub-Event")
	if !ok {
		writeWebhookError(writer, http.StatusBadRequest, "invalid_headers")
		return
	}
	signature, ok := exactWebhookHeader(request, "X-Hub-Signature-256")
	if !ok {
		writeWebhookError(writer, http.StatusUnauthorized, "unauthenticated")
		return
	}
	payload, tooLarge, readErr := readWebhookBody(request.Body)
	if tooLarge {
		writeWebhookError(writer, http.StatusRequestEntityTooLarge, "request_too_large")
		return
	}
	if readErr != nil {
		writeWebhookError(writer, http.StatusBadRequest, "invalid_payload")
		return
	}
	receivedAt := h.clock.Now()
	delivery, verifyErr := h.verifier.Verify(h.scope, deliveryID, eventType, signature, payload, receivedAt)
	switch {
	case errors.Is(verifyErr, ErrEventNotAllowed), errors.Is(verifyErr, ErrActionNotAllowed):
		writeWebhookJSON(writer, http.StatusAccepted, webhookResponse{Contract: "open-trestle/webhook-response", SchemaVersion: 1, Ignored: true})
		return
	case errors.Is(verifyErr, ErrInvalidSignature), errors.Is(verifyErr, ErrSignatureMismatch):
		writeWebhookError(writer, http.StatusUnauthorized, "unauthenticated")
		return
	case verifyErr != nil:
		writeWebhookError(writer, http.StatusBadRequest, "invalid_payload")
		return
	}
	receipt, created, acceptErr := h.inbox.Accept(request.Context(), delivery, receivedAt)
	if acceptErr != nil {
		if errors.Is(acceptErr, webhook.ErrInboxContextDone) || errors.Is(acceptErr, webhook.ErrInvalidInboxContext) {
			writeWebhookError(writer, http.StatusServiceUnavailable, "unavailable")
			return
		}
		if errors.Is(acceptErr, webhook.ErrDeliveryExpired) {
			writeWebhookError(writer, http.StatusGone, "delivery_expired")
			return
		}
		if errors.Is(acceptErr, webhook.ErrDeliveryConflict) {
			writeWebhookError(writer, http.StatusConflict, "delivery_conflict")
			return
		}
		writeWebhookError(writer, http.StatusInternalServerError, "persistence_failed")
		return
	}
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
	}
	writeWebhookJSON(writer, status, webhookResponse{Contract: "open-trestle/webhook-response", SchemaVersion: 1, AcceptanceIdentity: receipt.Identity(), Duplicate: !created})
	if h.notifier != nil {
		h.notifier.Notify(webhook.DeliveryNotice{Scope: delivery.Scope(), Source: delivery.Source(), DeduplicationKey: delivery.DeduplicationKey()})
	}
}
func exactWebhookHeader(request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	returnValue := ""
	if len(values) == 1 {
		returnValue = values[0]
	}
	return returnValue, len(values) == 1 && len(returnValue) > 0 && len(returnValue) <= maxWebhookHeaderBytes
}
func readWebhookBody(body io.ReadCloser) ([]byte, bool, error) {
	if body == nil {
		return nil, false, nil
	}
	defer body.Close()
	payload, err := io.ReadAll(io.LimitReader(body, maxHTTPWebhookBodyBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(payload) > maxHTTPWebhookBodyBytes {
		return nil, true, nil
	}
	return payload, false, nil
}

type webhookResponse struct {
	Contract           string `json:"contract"`
	SchemaVersion      int    `json:"schema_version"`
	AcceptanceIdentity string `json:"acceptance_identity,omitempty"`
	Duplicate          bool   `json:"duplicate,omitempty"`
	Ignored            bool   `json:"ignored,omitempty"`
	Error              string `json:"error,omitempty"`
}

func setWebhookHeaders(writer http.ResponseWriter) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
}
func writeWebhookError(writer http.ResponseWriter, status int, code string) {
	writeWebhookJSON(writer, status, webhookResponse{Contract: "open-trestle/webhook-response", SchemaVersion: 1, Error: code})
}
func writeWebhookJSON(writer http.ResponseWriter, status int, response webhookResponse) {
	encoded, err := json.Marshal(response)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}
