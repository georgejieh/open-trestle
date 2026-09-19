package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/apilimit"
)

func TestAPIResponseWriterRejectsOversizedEnvelope(t *testing.T) {
	oversized, err := json.Marshal(strings.Repeat("x", apilimit.MaximumResponseBytes))
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	writeAPIJSON(recorder, http.StatusOK, apiResponseRecord{Contract: "open-trestle/api-response", SchemaVersion: 1, RequestID: "request-a", Diagnostics: oversized})
	if recorder.Code != http.StatusInternalServerError || recorder.Body.Len() > 256 {
		t.Fatalf("oversized output emitted: status=%d bytes=%d", recorder.Code, recorder.Body.Len())
	}
}
