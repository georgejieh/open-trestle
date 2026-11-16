package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

// Route planners cannot import this package, so they count the schema framing
// through review.ModelRequestResponseFormatBytes. It must equal the framing this
// adapter serializes, and a reservation planned for the structured transport
// must pass the dispatch check for every request kind a local route carries.
func TestLocalStructuredOutputPlannedReservationCoversTheSentRequest(t *testing.T) {
	rawVerification := testRawVerificationRequest(t, "literal")
	var header struct {
		ReviewScopeIdentity string `json:"review_scope_identity"`
	}
	if err := json.Unmarshal(rawVerification.Payload(), &header); err != nil {
		t.Fatal(err)
	}
	sanitized, err := review.NewSanitizedModelRequest(header.ReviewScopeIdentity, rawVerification, rawVerification)
	if err != nil {
		t.Fatal(err)
	}
	sanitizedVerification, err := sanitized.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := review.NewLocalVerificationRequest(rawVerification, header.ReviewScopeIdentity)
	if err != nil {
		t.Fatal(err)
	}
	investigation := structuredInvestigationRequest(t)
	cases := []struct {
		name    string
		request provider.Request
		inner   []byte
	}{
		{"sanitized generation", testModelRequest(t), testRawModelRequest(t).Payload()},
		{"sanitized verification", sanitizedVerification, rawVerification.Payload()},
		{"local verification envelope", envelope, rawVerification.Payload()},
		{"investigation", investigation, investigation.Payload()},
	}
	declared, err := provider.NewModelCostBudget(1, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			format, err := localStructuredResponseFormat(tc.inner)
			if err != nil {
				t.Fatal(err)
			}
			framing, err := json.Marshal(struct {
				Format *chatResponseFormat `json:"response_format"`
			}{format})
			if err != nil {
				t.Fatal(err)
			}
			if got := review.ModelRequestResponseFormatBytes(tc.request); got != uint32(len(framing)) {
				t.Fatalf("planned response_format bytes = %d, adapter serializes %d", got, len(framing))
			}
			planned, err := review.ModelRequestBudgetForTransport(tc.request, declared, review.ModelRequestTransportLocalStructuredOutput)
			if err != nil {
				t.Fatal(err)
			}
			standard, err := review.ModelRequestBudget(tc.request, declared)
			if err != nil {
				t.Fatal(err)
			}
			for _, budget := range []provider.ModelCostBudget{standard, planned} {
				config := localStructuredConfig(t)
				transport := &structuredForbiddenTransport{}
				config.HTTPClient = &http.Client{Transport: transport}
				config.HTTPClientIdentity = strings.Repeat("b", 64)
				a, err := New(config)
				if err != nil {
					t.Fatal(err)
				}
				result := a.executeWithDispatchProof(context.Background(), testRoute(t, "model", ""), 100, tc.request, "", modelhandler.SanitizedDispatchProof{}, budget)
				refused := result.Failure() == gateway.RouteFailurePolicyDenied && result.ReplaySafety() == gateway.RouteReplayNotDispatched && transport.calls == 0
				if budget == standard && !refused {
					t.Fatal("a reservation without the schema framing reached the transport")
				}
				if budget == planned && (refused || transport.calls != 1) {
					t.Fatalf("planned structured reservation %d refused: %#v", planned.EstimatedInputTokens(), result)
				}
			}
		})
	}
}
