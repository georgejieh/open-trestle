package model

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

// skewedTurn dispatches the fixture's generation request through an owner whose
// measures over-count by the given bytes, so the turn record carries a
// self-consistent count that its own request does not support, and returns the
// matching unclaimed input and retained turn artifacts.
func skewedTurn(t *testing.T, systemSkew uint32, structured bool, formatSkew uint32) (artifactsFixture, artifact.Artifact, artifact.Artifact, InvestigationArtifactExpectations) {
	t.Helper()
	f := newArtifactsFixture(t)
	system := func(request provider.Request) uint32 {
		return review.ModelRequestSystemChannelBytes(request) + systemSkew
	}
	format := func(request provider.Request) uint32 {
		return review.ModelRequestResponseFormatBytes(request) + formatSkew
	}
	f.options.SystemChannelBytes = system
	if structured {
		f.options.GenerationResponseFormatBytes = format
	}
	owner, err := gateway.NewInvestigationRouteOwner(f.options)
	artifactsCheck(t, err)
	f.owner = owner
	expected := f.expected
	request, err := f.context.Context.ProviderRequest()
	artifactsCheck(t, err)
	formatBytes := uint32(0)
	if structured {
		formatBytes = format(request)
	}
	budget, err := gateway.InvestigationTurnCostBudget(f.options.Budget, request, system(request), formatBytes, f.options.Budget.MaxCostMicroUSD())
	artifactsCheck(t, err)
	input, err := gateway.NewReviewRoutingInput(f.options.Scope, request, f.options.Requirements, f.options.Constraints)
	artifactsCheck(t, err)
	route, performance, _ := artifactsRoute(t, "a")
	eligible, err := gateway.FilterEligibleRoutes(input, budget, 1, []gateway.ObservedRouteCandidate{route})
	artifactsCheck(t, err)
	pin, err := gateway.NewPinnedRouteRankingPolicy(route.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference(), nil)
	artifactsCheck(t, err)
	ranking, err := gateway.RankEligibleRoutes(eligible, pin, 1, []provider.RoutePerformanceObservation{performance})
	artifactsCheck(t, err)
	selection, err := gateway.NewRouteSelectionReceipt(eligible, ranking)
	artifactsCheck(t, err)
	predicted, err := gateway.NewInitialRouteAttemptAuthorization(request, selection, ranking)
	artifactsCheck(t, err)
	turn, err := owner.Dispatch(context.Background(), gateway.InvestigationGenerationTurn, request)
	artifactsCheck(t, err)
	if turn.Authorization().Identity() != predicted.Identity() {
		t.Fatal("fixture prediction differs from the owned turn")
	}
	turnBytes, err := gateway.EncodeInvestigationTurnRecord(turn)
	artifactsCheck(t, err)
	// A structured owner binds its role transports into its identity.
	var owned struct {
		Owner string `json:"owner_identity"`
	}
	artifactsCheck(t, json.Unmarshal(turnBytes, &owned))
	if (owned.Owner == expected.OwnerIdentity) == structured {
		t.Fatal("owner identity does not follow its transports")
	}
	expected.OwnerIdentity = owned.Owner
	inputArtifact, err := NewInvestigationGenerationInputArtifact(f.context, predicted, expected, f.clock.Now())
	artifactsCheck(t, err)
	expected.InputArtifactIdentity = inputArtifact.Identity()
	_, err = f.store.Put(context.Background(), inputArtifact, f.clock.Now())
	artifactsCheck(t, err)
	turnArtifact, err := artifact.New(expected.Scope, artifactsKind(t, "investigation_turn"), "application/json", f.context.ContextArtifact.Classification(), artifact.OriginHost, f.context.ContextArtifact.Protection(), []string{f.context.ContextArtifact.Identity(), inputArtifact.Identity(), expected.HeadSnapshotArtifactIdentity, turn.Identity(), turn.Authorization().Identity(), turn.Outcome().Identity(), turn.Reconciliation().Identity(), expected.OwnerIdentity}, turnBytes, f.clock.Now(), f.context.ContextArtifact.ExpiresAt())
	artifactsCheck(t, err)
	expected.TurnArtifactIdentity = turnArtifact.Identity()
	return f, inputArtifact, turnArtifact, expected
}

// internal/gateway cannot import internal/review, so it checks a recorded
// system channel or response_format count only against the recorded budget
// and identity. Turn readback in this package re-measures both from the
// recorded request and refuses a mismatch.
func TestInvestigationTurnReadbackRemeasuresTheRecordedTransportCounts(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		systemSkew, formatSkew uint32
		structured, refused    bool
	}{
		{name: "measured standard turn"},
		{name: "measured structured turn", structured: true},
		{name: "tampered system channel count", systemSkew: 1, refused: true},
		{name: "tampered structured system channel count", systemSkew: 1, structured: true, refused: true},
		{name: "tampered response_format count", formatSkew: 1, structured: true, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, input, turn, expected := skewedTurn(t, tc.systemSkew, tc.structured, tc.formatSkew)
			if _, err := gateway.ParseInvestigationTurnRecord(turn.Payload()); err != nil {
				t.Fatal("the gateway codec refused a self-consistent count")
			}
			_, parseErr := parseRetainedInvestigationTurn(turn.Payload())
			_, resultErr := NewInvestigationGenerationResultArtifact(input, f.context, turn, expected, f.clock.Now())
			if tc.refused != (parseErr != nil) || tc.refused != (resultErr != nil) {
				t.Fatalf("readback refused = (%v, %v), want refused %t", parseErr, resultErr, tc.refused)
			}
		})
	}
}
