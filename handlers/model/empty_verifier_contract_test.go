package model

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/testsupport"
)

func contractDocumentResult(t *testing.T, document string) gateway.RouteDispatchResult {
	t.Helper()
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(document))
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	if err != nil {
		t.Fatal(err)
	}
	result, err := gateway.NewSuccessfulRouteDispatchResult(response)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestVerificationHandlerEmptyCandidatesStillDispatchesIndependentVerifier(t *testing.T) {
	for _, tc := range []struct {
		name, document string
		success, reuse bool
	}{
		{"empty verdicts", `{"schema_version":1,"verdicts":[]}`, true, false},
		{"invented verdict", `{"schema_version":1,"verdicts":[{"candidate_id":"` + strings.Repeat("a", 64) + `","outcome":"rejected","severity":"none","rationale":"No issue.","evidence_ids":[]}]}`, false, false},
		{"generation receipt reuse", `{"schema_version":1,"verdicts":[]}`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			generatedResponse := contractDocumentResult(t, `{"schema_version":2,"candidates":[]}`)
			scope, store, ledger, contextArtifact, inputArtifact, generationArtifact, generation := completedGenerationFixtureWithDispatch(t, generatedResponse)
			if len(generation.Candidates().Findings()) != 0 {
				t.Fatal("fixture must have empty candidates")
			}
			verificationContext := generationContextForResult(t, contextArtifact, inputArtifact, generation)
			raw, err := verificationContext.ProviderRequest()
			if err != nil {
				t.Fatal(err)
			}
			sanitizer := testsupport.NewCleanVerificationSanitizer()
			sanitized, _, err := sanitizer.SanitizeVerification(context.Background(), raw, scope.Identity())
			if err != nil {
				t.Fatal(err)
			}
			request, err := sanitized.ProviderRequest()
			if err != nil {
				t.Fatal(err)
			}
			authorization := routeAuthorization(t, scope, request, "verifier-provider", "test-verifier", "primary/verifier", "verifier-model", "1", strings.Repeat("e", 64), strings.Repeat("f", 64))
			policy, err := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
			if err != nil {
				t.Fatal(err)
			}
			authority, err := NewVerificationAuthority(request, generation.RouteExecution(), authorization, policy)
			if err != nil {
				t.Fatal(err)
			}
			appendSelectionEvent(t, ledger, scope, authorization, time.UnixMilli(210))
			authorizer := &fixedVerificationAuthorizer{identity: strings.Repeat("a", 64), authority: authority}
			dispatched := contractDocumentResult(t, tc.document)
			if tc.reuse {
				dispatched = generatedResponse
			}
			dispatcher := &contractRecordingDispatcher{adapterID: "test-verifier", result: dispatched}
			catalog, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
			if err != nil {
				t.Fatal(err)
			}
			handler, err := NewVerificationHandler(store, catalog, ledger, authorizer, fixedClock{at: time.UnixMilli(220)}, sanitizer)
			if err != nil {
				t.Fatal(err)
			}
			completion := handler.Execute(context.Background(), verificationTaskRequest(t, scope, generationArtifact.Identity(), handler.HandlerIdentity()))
			if len(dispatcher.requests) != 1 || authorizer.calls != 1 {
				t.Fatal("empty candidate batch skipped independent verifier")
			}
			if dispatcher.requests[0].Identity() == generation.RouteExecution().Authorization().RequestIdentity() || dispatcher.requests[0].Identity() != authorization.RequestIdentity() {
				t.Fatal("empty verifier reused generation request authority")
			}
			if !tc.success {
				if completion.Status() != controlplane.TaskCompletionFailed || completion.OutputIdentity() != "" {
					t.Fatal("fabricated empty verdict or generation response admitted")
				}
				return
			}
			if completion.Status() != controlplane.TaskCompletionSucceeded {
				t.Fatalf("empty verification failed: %s", completion.Status())
			}
			output, err := store.Get(context.Background(), scope, completion.OutputIdentity(), time.UnixMilli(221))
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseStoredVerificationResultArtifact(context.Background(), store, time.UnixMilli(221), output, generationArtifact, inputArtifact, contextArtifact)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Verification().ResponseIdentity() != dispatched.Response().Identity() || parsed.Verification().CandidateBatchIdentity() != generation.Candidates().Identity() || len(parsed.Verification().Results()) != 0 || len(parsed.VerifiedFindings().Findings()) != 0 || parsed.RouteIndependence().Level() != gateway.RouteIndependenceDistinctProvider {
				t.Fatal("empty result lost actual response or independent lineage")
			}
			if !bytes.Equal(parsed.VerificationContext().Payload(), raw.Payload()) || parsed.VerificationContext().OutputSchemaIdentity() != review.ModelVerificationBatchSchemaIdentity {
				t.Fatal("empty readback changed verifier context")
			}
		})
	}
}
