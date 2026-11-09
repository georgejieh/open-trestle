package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/webhook"
)

// GetDeliveryRefusal reads the recorded refusal of the webhook delivery that
// owns a run scope. A delivery that was not refused returns an APIError with
// code not_found.
func (c *Client) GetDeliveryRefusal(ctx context.Context, scope audit.ReviewScope) (webhook.RefusalRecord, error) {
	if scope.Validate() != nil || c == nil || c.baseURL == nil || c.httpClient == nil || ctx == nil {
		return webhook.RefusalRecord{}, ErrInvalidClient
	}
	requestURL := *c.baseURL
	requestURL.Path = runPath(scope) + "/refusal"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return webhook.RefusalRecord{}, ErrInvalidClient
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+c.credential)
	request.Header.Set("User-Agent", "open-trestle-client/1")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if errors.Is(err, ErrRedirectRejected) {
			return webhook.RefusalRecord{}, ErrRedirectRejected
		}
		return webhook.RefusalRecord{}, fmt.Errorf("Open Trestle API request: %w", err)
	}
	defer response.Body.Close()
	encoded, tooLarge, err := readClientBody(response.Body)
	if err != nil || tooLarge {
		return webhook.RefusalRecord{}, ErrInvalidResponse
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return webhook.RefusalRecord{}, ErrInvalidResponse
	}
	if response.StatusCode != http.StatusOK {
		record, err := parseClientResponse(encoded)
		if err != nil || record.Error == nil {
			return webhook.RefusalRecord{}, ErrInvalidResponse
		}
		return webhook.RefusalRecord{}, &APIError{statusCode: response.StatusCode, requestID: record.RequestID, code: record.Error.Code, message: record.Error.Message}
	}
	var envelope struct {
		Contract      string          `json:"contract"`
		SchemaVersion int             `json:"schema_version"`
		RequestID     string          `json:"request_id"`
		Refusal       json.RawMessage `json:"refusal"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) != io.EOF || envelope.Contract != "open-trestle/delivery-refusal-response" || envelope.SchemaVersion != 1 || !validResponseValue(envelope.RequestID, 128) {
		return webhook.RefusalRecord{}, ErrInvalidResponse
	}
	record, err := webhook.ParseRefusalRecord(envelope.Refusal)
	if err != nil || record.Scope().TenantID() != scope.TenantID() || record.Scope().RepositoryID() != scope.RepositoryID() || "webhook-"+record.DeduplicationKey() != scope.ReviewRunID() {
		return webhook.RefusalRecord{}, ErrInvalidResponse
	}
	return record, nil
}
