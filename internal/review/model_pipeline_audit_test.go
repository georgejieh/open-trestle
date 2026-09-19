package review

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/gateway"
)

func modelPipelineArtifacts(t *testing.T) (audit.ReviewScope, ModelPipelineArtifacts) {
	t.Helper()
	generationContext, candidates, candidateOutput, verificationContext, verification, verificationOutput, independence := independentVerificationFixture(t, "verified")
	independent, err := NewIndependentVerificationReceipt(IndependentVerificationArtifacts{
		GenerationContext: generationContext, Candidates: candidates, CandidateOutput: candidateOutput,
		VerificationContext: verificationContext, Verification: verification,
		VerificationOutput: verificationOutput, RouteIndependence: independence,
	})
	if err != nil {
		t.Fatal(err)
	}
	set, err := PromoteVerifiedCandidates(independent, candidates, verification)
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := NewPublicationPolicy(SeverityLow, 10, gateway.RouteIndependenceDistinctProvider, true)
	readiness, err := EvaluatePublicationReadiness(policy, independent, set)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	return scope, ModelPipelineArtifacts{
		GenerationContext: generationContext, CandidateOutput: candidateOutput, Candidates: candidates,
		VerificationContext: verificationContext, VerificationOutput: verificationOutput, Verification: verification,
		RouteIndependence: independence, IndependentVerification: independent,
		VerifiedFindings: set, PublicationReadiness: readiness,
	}
}

func TestRecordModelPipelineAuditAppendsCompleteIdempotentLineage(t *testing.T) {
	scope, artifacts := modelPipelineArtifacts(t)
	ledger := audit.NewMemoryLedger()
	receipt, err := RecordModelPipelineAudit(context.Background(), ledger, scope, artifacts, time.UnixMilli(1_700_000_000_000))
	if err != nil {
		t.Fatal(err)
	}
	events := receipt.Events()
	if receipt.Identity() == "" || receipt.ReviewScopeIdentity() != scope.Identity() || len(events) != 7 || receipt.Validate() != nil {
		t.Fatalf("pipeline audit receipt did not round trip: %#v", receipt)
	}
	wantKinds := []audit.EventKind{
		audit.EventContextSourcesSelected, audit.EventContextPacketAssembled, audit.EventCandidateBatchAdmitted,
		audit.EventVerificationContextAssembled, audit.EventVerificationBatchAdmitted,
		audit.EventIndependentVerificationCompleted, audit.EventPublicationReadinessEvaluated,
	}
	for index, event := range events {
		if event.Kind() != wantKinds[index] || event.Scope() != scope || event.Validate() != nil {
			t.Fatalf("event %d = %#v", index, event)
		}
	}
	again, err := RecordModelPipelineAudit(context.Background(), ledger, scope, artifacts, time.UnixMilli(1_800_000_000_000))
	if err != nil || again.Identity() != receipt.Identity() {
		t.Fatalf("idempotent audit = (%#v, %v)", again, err)
	}
	stored, _ := ledger.Read(context.Background(), scope, 0, 20)
	if len(stored) != 7 {
		t.Fatalf("stored event count = %d", len(stored))
	}
	events[0] = audit.Event{}
	if receipt.Events()[0].Identity() == "" {
		t.Fatal("audit receipt exposed mutable events")
	}
}

func TestRecordModelPipelineAuditRejectsScopeAndArtifactMismatch(t *testing.T) {
	scope, artifacts := modelPipelineArtifacts(t)
	otherScope, _ := audit.NewReviewScope("other", "repository", "review-run")
	if receipt, err := RecordModelPipelineAudit(context.Background(), audit.NewMemoryLedger(), otherScope, artifacts, time.UnixMilli(1)); !errors.Is(err, ErrModelPipelineAuditScopeMismatch) || receipt.Identity() != "" {
		t.Fatalf("cross-scope audit = (%#v, %v)", receipt, err)
	}
	artifacts.CandidateOutput, artifacts.VerificationOutput = artifacts.VerificationOutput, artifacts.CandidateOutput
	if receipt, err := RecordModelPipelineAudit(context.Background(), audit.NewMemoryLedger(), scope, artifacts, time.UnixMilli(1)); err == nil || receipt.Identity() != "" {
		t.Fatalf("cross-wired audit = (%#v, %v)", receipt, err)
	}
}

func TestReviewPipelineAuditReceiptRejectsTampering(t *testing.T) {
	scope, artifacts := modelPipelineArtifacts(t)
	receipt, _ := RecordModelPipelineAudit(context.Background(), audit.NewMemoryLedger(), scope, artifacts, time.UnixMilli(1))
	forged := receipt
	forged.identity = strings.Repeat("f", 64)
	if !errors.Is(forged.Validate(), ErrInvalidModelPipelineAuditReceiptIdentity) {
		t.Fatal("forged pipeline audit receipt accepted")
	}
}

func TestRecordModelPipelineAuditIsConcurrentIdempotent(t *testing.T) {
	scope, artifacts := modelPipelineArtifacts(t)
	ledger := audit.NewMemoryLedger()
	receipts := make(chan ModelPipelineAuditReceipt, 2)
	errorsSeen := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			receipt, err := RecordModelPipelineAudit(context.Background(), ledger, scope, artifacts, time.UnixMilli(1))
			receipts <- receipt
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(receipts)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	identity := ""
	for receipt := range receipts {
		if identity == "" {
			identity = receipt.Identity()
		}
		if receipt.Identity() != identity {
			t.Fatal("concurrent audit returned different receipts")
		}
	}
	events, _ := ledger.Read(context.Background(), scope, 0, 20)
	if len(events) != 7 {
		t.Fatalf("stored event count = %d", len(events))
	}
}
