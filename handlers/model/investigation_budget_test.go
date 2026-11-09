package model_test

import (
	"context"
	"testing"

	model "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
)

// The OpenAI-compatible adapter recomputes review.ModelRequestBudget from the
// approved budget and refuses a request whose approved input estimate is below
// it. An investigation turn must therefore be planned with the system channel
// the adapter sends, for both the generation request and the local
// verification envelope.
func TestInvestigationTurnReservationCountsTheTrustedSystemChannel(t *testing.T) {
	ctx := context.Background()
	options, _, a, b, _, _ := upperFixture(t, "")
	controller, err := model.NewInvestigation(ctx, options)
	upperCheck(t, err)
	first, err := controller.Step(ctx)
	upperCheck(t, err)
	_, err = controller.Step(ctx)
	upperCheck(t, err)
	generation, err := controller.Generate(ctx)
	upperCheck(t, err)
	verified, err := controller.Verify(ctx)
	upperCheck(t, err)
	if a.count() != 3 || b.count() != 1 {
		t.Fatal("fixture did not dispatch three generation turns and one verification turn")
	}
	cases := []struct {
		name string
		turn gateway.InvestigationTurnRecord
		call gateway.RouteDispatchRequest
	}{
		{"first generation", first.Turn(), a.calls[0]},
		{"final generation", generation.FinalTurn(), a.calls[2]},
		{"local verification envelope", verified.FinalTurn(), b.calls[0]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := tc.call.Request()
			if tc.turn.RequestIdentity() != request.Identity() || tc.call.Authorization().Identity() != tc.turn.Authorization().Identity() {
				t.Fatal("fixture compared a different dispatched request")
			}
			system := review.ModelRequestSystemChannelBytes(request)
			if system == 0 {
				t.Fatal("fixture request has no trusted system channel")
			}
			approved := tc.turn.Authorization().CostBudget()
			required, err := review.ModelRequestBudget(request, approved)
			if err != nil {
				t.Fatal(err)
			}
			if approved.EstimatedInputTokens() < required.EstimatedInputTokens() {
				t.Fatalf("approved input estimate %d is below the adapter's host estimate %d (system channel %d bytes)", approved.EstimatedInputTokens(), required.EstimatedInputTokens(), system)
			}
			if uint64(approved.EstimatedInputTokens()) != uint64(len(request.Payload()))+uint64(system)+256 {
				t.Fatalf("approved input estimate %d, want payload %d + system %d + 256", approved.EstimatedInputTokens(), len(request.Payload()), system)
			}
		})
	}
}
