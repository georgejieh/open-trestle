package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/georgejieh/open-trestle/controlplane"
)

func TestRenewalBudgetFailureHasDedicatedConflictCode(t *testing.T) {
	recorder := httptest.NewRecorder()
	(&Server{}).writeCoordinatorError(recorder, "request-budget", controlplane.ErrTaskLeaseRenewalLimit)
	var response apiResponseRecord
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusConflict || response.Error == nil || response.Error.Code != "lease_renewal_limit" || response.RequestID != "request-budget" {
		t.Fatalf("unexpected renewal refusal: status=%d response=%s", recorder.Code, recorder.Body.Bytes())
	}
}
