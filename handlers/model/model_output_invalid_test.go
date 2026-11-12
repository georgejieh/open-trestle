package model

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/testsupport"
)

// Every answer below is a synthetic fixture. A reply the adapter accepted and
// that stopped normally, but whose answer is not a valid review document,
// fails the model task as internal with the content-free reason
// model_output_invalid. A reply that stopped for another reason keeps the
// bare internal failure, and nothing records the answer's text.

func providerAnswerResult(t *testing.T, kind provider.ResponsePartKind, finish provider.ResponseFinishReason, payload string) gateway.RouteDispatchResult {
	t.Helper()
	mediaType := "text/plain; charset=utf-8"
	if kind == provider.ResponsePartStructuredData {
		mediaType = "application/json"
	}
	part, err := provider.NewResponsePart(kind, mediaType, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	usage, _ := provider.NewRouteTokenUsage(10, 5, 0)
	response, err := provider.NewResponse(provider.CapabilityReviewV1, finish, []provider.ResponsePart{part}, usage)
	if err != nil {
		t.Fatal(err)
	}
	result, err := gateway.NewSuccessfulRouteDispatchResult(response)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

const invalidAnswerLeak = "MODEL_ANSWER_TEXT_MUST_NOT_BE_RECORDED"

type invalidAnswer struct {
	name   string
	result func(*testing.T) gateway.RouteDispatchResult
	reason controlplane.TaskFailureReason
}

func invalidGenerationAnswers() []invalidAnswer {
	document := `{"schema_version":1,"candidates":[{"title":"Issue","claim":"` + invalidAnswerLeak + `","severity_hint":"high","source_range":{"source_id":"source-1","start_line":1,"end_line":1},"evidence_ids":["source-1"]}]}`
	return []invalidAnswer{
		{"chat-template tokens", func(t *testing.T) gateway.RouteDispatchResult {
			return providerAnswerResult(t, provider.ResponsePartAssistantText, provider.ResponseFinishStop, "<|start|>assistant<|channel|>final <|constrain|>json<|message|>"+document+"<|return|>")
		}, controlplane.TaskFailureReasonModelOutputInvalid},
		{"control character in a string", func(t *testing.T) gateway.RouteDispatchResult {
			return providerAnswerResult(t, provider.ResponsePartAssistantText, provider.ResponseFinishStop, strings.Replace(document, "Issue", "Iss\x01ue", 1))
		}, controlplane.TaskFailureReasonModelOutputInvalid},
		{"wrong shape", func(t *testing.T) gateway.RouteDispatchResult {
			return providerAnswerResult(t, provider.ResponsePartStructuredData, provider.ResponseFinishStop, `{"schema_version":1,"findings":["`+invalidAnswerLeak+`"]}`)
		}, controlplane.TaskFailureReasonModelOutputInvalid},
		{"refusal", func(t *testing.T) gateway.RouteDispatchResult {
			return providerAnswerResult(t, provider.ResponsePartRefusal, provider.ResponseFinishStop, invalidAnswerLeak)
		}, controlplane.TaskFailureReasonModelOutputInvalid},
		// A complete document that stopped at the length limit, or one a
		// content filter stopped, is not reported as the model's invalid answer.
		{"complete document at a length stop", func(t *testing.T) gateway.RouteDispatchResult {
			return providerAnswerResult(t, provider.ResponsePartStructuredData, provider.ResponseFinishLength, document)
		}, 0},
		{"content filter", func(t *testing.T) gateway.RouteDispatchResult {
			return providerAnswerResult(t, provider.ResponsePartRefusal, provider.ResponseFinishContentFilter, invalidAnswerLeak)
		}, 0},
	}
}

func TestGenerationHandlerRecordsAnInvalidModelAnswer(t *testing.T) {
	for _, test := range invalidGenerationAnswers() {
		t.Run(test.name, func(t *testing.T) {
			scope, snapshot, packet, contextArtifact, providerRequest := generationContextFixture(t)
			authorization := generationAuthorization(t, scope, providerRequest)
			dispatcher := &recordingDispatcher{adapterID: "test-model", result: test.result(t)}
			catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
			ledger := audit.NewMemoryLedger()
			seedRouteSelection(t, ledger, scope, authorization)
			store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
			_, _ = store.Put(context.Background(), contextArtifact, time.UnixMilli(60))
			handler, _ := newLegacyGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(200)})
			input, _ := NewGenerationInput(contextArtifact, packet, snapshot, authorization)
			inputArtifact, _ := NewGenerationInputArtifact(input, contextArtifact, []string{strings.Repeat("4", 64)}, time.UnixMilli(70))
			_, _ = store.Put(context.Background(), inputArtifact, time.UnixMilli(70))
			completion := handler.Execute(context.Background(), generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1))
			if completion.Status() != controlplane.TaskCompletionFailed || completion.Validate() != nil || completion.Failure() != controlplane.RunFailureInternal || completion.FailureReason() != test.reason || completion.OutputIdentity() != "" || dispatcher.calls != 1 {
				t.Fatalf("completion failure=%s reason=%q calls=%d", completion.Failure(), completion.FailureReason(), dispatcher.calls)
			}
			encoded, err := controlplane.EncodeTaskCompletion(completion)
			if err != nil || strings.Contains(string(encoded), invalidAnswerLeak) || strings.Contains(string(encoded), "<|") {
				t.Fatalf("the completion carried the answer: %s %v", encoded, err)
			}
		})
	}
	// A valid answer still succeeds.
	scope, snapshot, packet, contextArtifact, providerRequest := generationContextFixture(t)
	authorization := generationAuthorization(t, scope, providerRequest)
	dispatcher := &recordingDispatcher{adapterID: "test-model", result: successfulProviderResult(t)}
	catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
	ledger := audit.NewMemoryLedger()
	seedRouteSelection(t, ledger, scope, authorization)
	store, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	_, _ = store.Put(context.Background(), contextArtifact, time.UnixMilli(60))
	handler, _ := newLegacyGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(200)})
	input, _ := NewGenerationInput(contextArtifact, packet, snapshot, authorization)
	inputArtifact, _ := NewGenerationInputArtifact(input, contextArtifact, []string{strings.Repeat("4", 64)}, time.UnixMilli(70))
	_, _ = store.Put(context.Background(), inputArtifact, time.UnixMilli(70))
	if completion := handler.Execute(context.Background(), generationTaskRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity(), 1)); completion.Status() != controlplane.TaskCompletionSucceeded {
		t.Fatalf("a valid answer failed: %s", completion.Failure())
	}
}

func TestVerificationHandlerRecordsAnInvalidModelAnswer(t *testing.T) {
	for _, test := range []invalidAnswer{
		{"chat-template tokens", func(t *testing.T) gateway.RouteDispatchResult {
			return providerAnswerResult(t, provider.ResponsePartAssistantText, provider.ResponseFinishStop, `<|channel|>final<|message|>{"schema_version":1,"verdicts":[]}<|return|>`)
		}, controlplane.TaskFailureReasonModelOutputInvalid},
		{"a missing verdict", func(t *testing.T) gateway.RouteDispatchResult {
			return providerAnswerResult(t, provider.ResponsePartStructuredData, provider.ResponseFinishStop, `{"schema_version":1,"verdicts":[]}`)
		}, controlplane.TaskFailureReasonModelOutputInvalid},
		{"complete document at a length stop", func(t *testing.T) gateway.RouteDispatchResult {
			return providerAnswerResult(t, provider.ResponsePartStructuredData, provider.ResponseFinishLength, `{"schema_version":1,"verdicts":[]}`)
		}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope, store, ledger, contextArtifact, inputArtifact, generationArtifact, generation := completedGenerationFixture(t)
			verificationContext := generationContextForResult(t, contextArtifact, inputArtifact, generation)
			rawVerificationRequest, _ := verificationContext.ProviderRequest()
			sanitizer := testsupport.NewCleanVerificationSanitizer()
			sanitizedVerification, _, err := sanitizer.SanitizeVerification(context.Background(), rawVerificationRequest, scope.Identity())
			if err != nil {
				t.Fatal(err)
			}
			verificationRequest, err := sanitizedVerification.ProviderRequest()
			if err != nil {
				t.Fatal(err)
			}
			verificationAuthorization := routeAuthorization(t, scope, verificationRequest, "verifier-provider", "test-verifier", "primary/verifier", "verifier-model", "1", strings.Repeat("e", 64), strings.Repeat("f", 64))
			policy, _ := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
			authority, err := NewVerificationAuthority(verificationRequest, generation.RouteExecution(), verificationAuthorization, policy)
			if err != nil {
				t.Fatal(err)
			}
			appendSelectionEvent(t, ledger, scope, verificationAuthorization, time.UnixMilli(210))
			authorizer := &fixedVerificationAuthorizer{identity: strings.Repeat("a", 64), authority: authority}
			dispatcher := &recordingDispatcher{adapterID: "test-verifier", result: test.result(t)}
			catalog, _ := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{dispatcher})
			handler, err := NewVerificationHandler(store, catalog, ledger, authorizer, fixedClock{at: time.UnixMilli(220)}, sanitizer)
			if err != nil {
				t.Fatal(err)
			}
			completion := handler.Execute(context.Background(), verificationTaskRequest(t, scope, generationArtifact.Identity(), handler.HandlerIdentity()))
			if completion.Status() != controlplane.TaskCompletionFailed || completion.Validate() != nil || completion.Failure() != controlplane.RunFailureInternal || completion.FailureReason() != test.reason || dispatcher.calls != 1 {
				t.Fatalf("completion failure=%s reason=%q calls=%d", completion.Failure(), completion.FailureReason(), dispatcher.calls)
			}
		})
	}
}
