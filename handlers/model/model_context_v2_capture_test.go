package model

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

func TestModelContextV2HistoricalReadbackRejectsNewAuthority(t *testing.T) {
	encoded, err := os.ReadFile("testdata/model-context-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	if hex.EncodeToString(digest[:]) != "f218aebf2f0b30a51a3b51b350beba243a8055024209ad253714948f8fb76ca3" {
		t.Fatal("historical artifact fixture changed")
	}
	var bundle struct {
		SchemaVersion               int             `json:"schema_version"`
		GenerationContext           json.RawMessage `json:"generation_context"`
		GenerationInput             json.RawMessage `json:"generation_input"`
		GenerationResult            json.RawMessage `json:"generation_result"`
		VerificationResult          json.RawMessage `json:"verification_result"`
		VerificationRequest         json.RawMessage `json:"verification_request"`
		VerificationRequestIdentity string          `json:"verification_request_identity"`
	}
	if err := json.Unmarshal(encoded, &bundle); err != nil || bundle.SchemaVersion != 1 {
		t.Fatalf("invalid historical bundle: %v", err)
	}
	values := make([]artifact.Artifact, 4)
	for index, record := range []json.RawMessage{bundle.GenerationContext, bundle.GenerationInput, bundle.GenerationResult, bundle.VerificationResult} {
		values[index], err = artifact.Parse(record)
		if err != nil {
			t.Fatal(err)
		}
		again, err := artifact.Encode(values[index])
		if err != nil || !bytes.Equal(again, record) {
			t.Fatal("historical artifact encoding changed")
		}
	}
	contextArtifact, inputArtifact, generationArtifact, verificationArtifact := values[0], values[1], values[2], values[3]
	input, err := ParseGenerationInput(inputArtifact.Payload())
	if err != nil {
		t.Fatal(err)
	}
	inputAgain, err := EncodeGenerationInput(input)
	if err != nil || !bytes.Equal(inputAgain, inputArtifact.Payload()) {
		t.Fatal("historical generation input changed")
	}
	generation, err := ParseGenerationResultArtifact(generationArtifact, inputArtifact, contextArtifact)
	if err != nil {
		t.Fatal(err)
	}
	generationAgain, err := encodeGenerationResult(generation)
	if err != nil || !bytes.Equal(generationAgain, generationArtifact.Payload()) {
		t.Fatal("historical generation result changed")
	}
	verification, err := ParseVerificationResultArtifact(verificationArtifact, generationArtifact, inputArtifact, contextArtifact)
	if err != nil {
		t.Fatal(err)
	}
	verificationAgain, err := encodeVerificationResult(verification)
	if err != nil || !bytes.Equal(verificationAgain, verificationArtifact.Payload()) {
		t.Fatal("historical verification result changed")
	}
	if verification.VerificationContext().Validate() != nil || !bytes.Equal(verification.VerificationContext().Payload(), bundle.VerificationRequest) || len(verification.VerifiedFindings().Findings()) != 1 || verification.IndependentReceipt().VerifiedCount() != 1 {
		t.Fatal("historical verifier request, findings, or lineage changed")
	}
	recordedRequest, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", verification.VerificationContext().Payload())
	if err != nil || recordedRequest.Identity() != bundle.VerificationRequestIdentity || recordedRequest.Identity() != verification.RouteExecution().Authorization().RequestIdentity() {
		t.Fatal("historical verifier request identity changed")
	}
	if request, err := verification.VerificationContext().ProviderRequest(); err == nil || request.Identity() != "" {
		t.Fatal("historical verifier readback granted execution")
	}
	if _, err := review.NewVerificationRequestContext(contextArtifact.Payload(), input.ContextIdentity(), input.ReviewScopeIdentity(), input.MemoryScopeIdentity(), input.MemoryIdentity(), input.Snapshot(), input.EvidenceItems(), generation.Candidates()); err == nil {
		t.Fatal("historical generation received new verifier authority")
	}
	scope := contextArtifact.Scope()
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if _, err := store.Put(context.Background(), value, time.UnixMilli(221)); err != nil {
			t.Fatal(err)
		}
	}
	ledger := audit.NewMemoryLedger()
	generationDispatcher := &recordingDispatcher{adapterID: "test-model", result: successfulProviderResult(t)}
	verificationDispatcher := &recordingDispatcher{adapterID: "test-verifier", result: verificationProviderResult(t, generation.Candidates())}
	catalog, err := gateway.NewRouteDispatcherCatalog([]gateway.RouteDispatcher{generationDispatcher, verificationDispatcher})
	if err != nil {
		t.Fatal(err)
	}
	generationHandler, err := NewGenerationHandler(store, catalog, ledger, fixedClock{at: time.UnixMilli(230)})
	if err != nil {
		t.Fatal(err)
	}
	generationCompletion := generationHandler.Execute(context.Background(), generationTaskRequest(t, scope, inputArtifact.Identity(), generationHandler.HandlerIdentity(), 1))
	if generationCompletion.Status() != controlplane.TaskCompletionFailed || generationDispatcher.calls != 0 {
		t.Fatal("historical generation input reached model dispatch")
	}
	authorizer := &fixedVerificationAuthorizer{identity: strings.Repeat("a", 64)}
	verificationHandler, err := NewVerificationHandler(store, catalog, ledger, authorizer, fixedClock{at: time.UnixMilli(230)})
	if err != nil {
		t.Fatal(err)
	}
	verificationCompletion := verificationHandler.Execute(context.Background(), verificationTaskRequest(t, scope, generationArtifact.Identity(), verificationHandler.HandlerIdentity()))
	if verificationCompletion.Status() != controlplane.TaskCompletionFailed || authorizer.calls != 0 || verificationDispatcher.calls != 0 {
		t.Fatal("historical generation result reached verifier authorization or dispatch")
	}
	events, err := ledger.Read(context.Background(), scope, 0, 10)
	if err != nil || len(events) != 0 {
		t.Fatal("historical execution reached route accounting")
	}
}
