package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/webhook"
)

// DeliveryRefusalReader returns the recorded refusal of the webhook delivery
// that owns a review run scope, if intake refused it before opening a run.
type DeliveryRefusalReader interface {
	DeliveryRefusal(context.Context, audit.ReviewScope) (webhook.RefusalRecord, bool, error)
}

// WithDeliveryRefusals returns a server clone that answers the read-only
// refusal route. Configure the clone before serving requests.
func (s *Server) WithDeliveryRefusals(reader DeliveryRefusalReader) (*Server, error) {
	if s == nil || reader == nil {
		return nil, ErrInvalidServer
	}
	if value := reflect.ValueOf(reader); value.Kind() == reflect.Pointer && value.IsNil() {
		return nil, ErrInvalidServer
	}
	clone := *s
	clone.refusalReader = reader
	return &clone, nil
}

// handleRunRefusal answers GET /api/v1/tenants/{tenant}/repositories/{repository}/runs/{run}/refusal
// with the content-free refusal record, or not_found when none is recorded.
func (s *Server) handleRunRefusal(ctx context.Context, writer http.ResponseWriter, request *http.Request, requestID string, principal Principal, scope audit.ReviewScope) {
	if request.Method != http.MethodGet {
		writeMethodNotAllowed(writer, requestID, http.MethodGet)
		return
	}
	if !principalAllowsScope(principal, scope) || !principal.HasCapability(CapabilityRunRead) {
		writeForbidden(writer, requestID)
		return
	}
	if !requestHasEmptyBody(request) {
		writeAPIError(writer, http.StatusBadRequest, requestID, "invalid_request", "This endpoint does not accept a request body.")
		return
	}
	if s.refusalReader == nil {
		writeAPIError(writer, http.StatusNotFound, requestID, "not_found", "No delivery refusal is recorded for this run.")
		return
	}
	record, found, err := s.refusalReader.DeliveryRefusal(ctx, scope)
	if err != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, requestID, "unavailable", "Delivery refusals could not be read.")
		return
	}
	if !found {
		writeAPIError(writer, http.StatusNotFound, requestID, "not_found", "No delivery refusal is recorded for this run.")
		return
	}
	encodedRecord, err := webhook.EncodeRefusalRecord(record)
	if err != nil || record.Scope().TenantID() != scope.TenantID() || record.Scope().RepositoryID() != scope.RepositoryID() || "webhook-"+record.DeduplicationKey() != scope.ReviewRunID() {
		writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "Delivery refusals could not be read.")
		return
	}
	encoded, err := json.Marshal(struct {
		Contract      string          `json:"contract"`
		SchemaVersion int             `json:"schema_version"`
		RequestID     string          `json:"request_id"`
		Refusal       json.RawMessage `json:"refusal"`
	}{"open-trestle/delivery-refusal-response", 1, requestID, encodedRecord})
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, requestID, "internal_error", "Delivery refusals could not be read.")
		return
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}
