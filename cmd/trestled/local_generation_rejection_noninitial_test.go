//go:build unix

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

// This is a synthetic retained receipt, not a provider execution or a startup proof.
func testGenerationRejectionNoninitial(t *testing.T, events []audit.Event, value, inputArtifact, packet, requestArtifact, receiptArtifact artifact.Artifact, descriptor controlplane.ContextInputDescriptor, route runtimecatalog.LocalGenerationRoutePlan, handler string, now time.Time) {
	t.Helper()
	original, err := modelhandler.ParseGenerationRejectionArtifact(value, inputArtifact, packet)
	if err != nil {
		t.Fatal(err)
	}
	initial := original.Attempt().Authorization()
	zero, err := provider.NewRouteTokenUsage(0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := gateway.NewFailedRouteAttemptOutcome(initial, gateway.RouteFailureTimeout, gateway.RouteReplayNoSideEffect, zero, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	settled, err := gateway.ReconcileAuthorizedRouteAttemptCost(initial, failed)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := gateway.NewRouteRetryPolicy(3, 100, 1000, 0, 2000)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := gateway.EvaluateRouteAttemptRetry(policy, initial, failed)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := gateway.NewRouteRetryAttemptAuthorization(initial, failed, settled, decision)
	if err != nil {
		t.Fatal(err)
	}
	if retry.Validate() != nil || retry.Kind() != gateway.RouteAttemptRetry || retry.AttemptOrdinal() != 2 || retry.RouteAttemptOrdinal() != 2 || retry.PreviousOutcomeIdentity() != failed.Identity() || retry.ContinuationDecisionIdentity() != decision.Identity() {
		t.Fatal("retry lineage invalid")
	}
	oldInput, err := modelhandler.ParseGenerationInput(inputArtifact.Payload())
	if err != nil {
		t.Fatal(err)
	}
	oldAuthorization, err := gateway.EncodeRouteAttemptAuthorization(initial)
	if err != nil {
		t.Fatal(err)
	}
	newAuthorization, err := gateway.EncodeRouteAttemptAuthorization(retry)
	if err != nil {
		t.Fatal(err)
	}
	replace := func(payload, old, new []byte) []byte {
		t.Helper()
		if bytes.Count(payload, old) != 1 {
			t.Fatal("fixture replacement not unique")
		}
		return bytes.Replace(payload, old, new, 1)
	}
	quoted := func(s string) []byte {
		encoded, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	payload := replace(inputArtifact.Payload(), oldAuthorization, newAuthorization)
	payload = replace(payload, quoted(oldInput.Identity()), quoted(""))
	digest := sha256.Sum256(payload)
	payload = replace(payload, []byte(`"identity":""`), []byte(`"identity":"`+hex.EncodeToString(digest[:])+`"`))
	input, err := modelhandler.ParseGenerationInput(payload)
	if err != nil {
		t.Fatal(err)
	}
	linked, err := modelhandler.NewGenerationInputArtifact(input, packet, nil, inputArtifact.CreatedAt())
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := gateway.NewSuccessfulRouteAttemptOutcome(retry, original.Attempt().Outcome().ResponseIdentity(), zero, 1)
	if err != nil {
		t.Fatal(err)
	}
	cost, err := gateway.ReconcileAuthorizedRouteAttemptCost(retry, outcome)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := gateway.NewCompletedRouteAttemptRecord(retry, outcome, cost)
	if err != nil {
		t.Fatal(err)
	}
	oldAttempt, err := gateway.EncodeCompletedRouteAttemptRecord(original.Attempt())
	if err != nil {
		t.Fatal(err)
	}
	newAttempt, err := gateway.EncodeCompletedRouteAttemptRecord(attempt)
	if err != nil {
		t.Fatal(err)
	}
	rejectionPayload := replace(value.Payload(), oldAttempt, newAttempt)
	rejectionPayload = replace(rejectionPayload, quoted(inputArtifact.Identity()), quoted(linked.Identity()))
	preimage, err := json.Marshal([]any{"open-trestle/model-generation-rejection", 1, linked.Identity(), packet.Identity(), input.ContextIdentity(), handler, attempt.Identity(), "candidate_document_shape"})
	if err != nil {
		t.Fatal(err)
	}
	rejectionDigest := sha256.Sum256(preimage)
	rejectionPayload = replace(rejectionPayload, quoted(original.Identity()), quoted(hex.EncodeToString(rejectionDigest[:])))
	receipt, err := artifact.New(value.Scope(), value.Kind(), value.MediaType(), value.Classification(), value.Origin(), value.Protection(), []string{linked.Identity(), packet.Identity(), handler, attempt.Identity(), requestArtifact.Identity(), receiptArtifact.Identity()}, rejectionPayload, value.CreatedAt(), value.ExpiresAt())
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := modelhandler.ParseGenerationRejectionArtifact(receipt, linked, packet)
	if err != nil || parsed.Attempt().Authorization().Identity() != retry.Identity() {
		t.Fatalf("coherent retry receipt refused: %v", err)
	}
	descriptor.Input = localInputArtifactDescriptor(linked)
	descriptor.GenerationInputIdentity = input.Identity()
	descriptor.AuthorizationIdentity = retry.Identity()
	dispatch, err := attempt.DispatchResultIdentity()
	if err != nil {
		t.Fatal(err)
	}
	subjects := []string{retry.SelectionReceiptIdentity(), retry.Identity(), outcome.Identity(), cost.Identity(), receipt.Identity()}
	parents := [][]string{{route.RoutingInputIdentity(), route.SelectedRecordIdentity(), route.RankingPolicyIdentity()}, {retry.SelectionReceiptIdentity()}, {retry.Identity(), dispatch, outcome.ResponseIdentity()}, {retry.Identity(), outcome.Identity()}, {linked.Identity(), packet.Identity(), attempt.Identity()}}
	rebuilt := make([]audit.Event, len(events))
	previous := ""
	for i, event := range events {
		current, err := audit.NewEvent(event.Scope(), uint64(i+1), previous, event.Kind(), subjects[i], parents[i], time.UnixMilli(event.OccurredAtUnixMilliseconds()))
		if err != nil {
			t.Fatal(err)
		}
		rebuilt[i], previous = current, current.Identity()
	}
	if err := validateGenerationRejectionAudit(rebuilt, receipt, linked, packet, requestArtifact, receiptArtifact, descriptor, route, handler, now); !errors.Is(err, errGenerationRejectionAudit) {
		t.Fatalf("coherent noninitial receipt admitted: %v", err)
	}
}
