package runtimecatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func readableGenerationRequest(t *testing.T) (audit.ReviewScope, provider.Request) {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant", "repository", "run")
	if err != nil {
		t.Fatal(err)
	}
	generation, _ := readableModelRequests(t, scope)
	return scope, generation
}

func readableModelRequests(t *testing.T, scope audit.ReviewScope) (provider.Request, provider.Request) {
	t.Helper()
	memoryScope, err := memory.NewScope(scope.TenantID(), scope.RepositoryID(), "actor", memory.RefVisibilityExact, strings.Repeat("a", 64), []string{"src"})
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("return value\n")
	sourceRange, err := evidence.NewSourceRange("src/main.go", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := review.NewReviewSnapshot("workspace", strings.Repeat("b", 64), []evidence.SourceRange{sourceRange})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	item, err := evidence.NewEvidenceItem("source-1", evidence.EvidenceKindSource, hex.EncodeToString(digest[:]), sourceRange)
	if err != nil {
		t.Fatal(err)
	}
	source, err := review.NewContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, item, content)
	if err != nil {
		t.Fatal(err)
	}
	index := memory.NewLexicalIndex()
	query, err := memory.NewLexicalQuery(memoryScope, "src/main.go", nil, nil, time.UnixMilli(100), 5)
	if err != nil {
		t.Fatal(err)
	}
	retrieval, err := index.Search(context.Background(), memoryScope, query)
	if err != nil {
		t.Fatal(err)
	}
	limits, err := review.NewContextLimits(1<<20, 0)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := review.NewContextPacket(scope, memoryScope, snapshot, review.ContextTaskCandidateGeneration, []review.ContextSource{source}, retrieval, limits)
	if err != nil {
		t.Fatal(err)
	}
	generationRequest, err := generation.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(`{"schema_version":1,"candidates":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, provider.NewUnknownRouteTokenUsage())
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := review.ParseCandidateBatch(response, snapshot, generation.EvidenceItems())
	if err != nil {
		t.Fatal(err)
	}
	verification, err := review.NewVerificationContextPacket(generation, candidates)
	if err != nil {
		t.Fatal(err)
	}
	verificationRequest, err := verification.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	return generationRequest, verificationRequest
}

func TestGenerationRouteFactoryBudgetsFullReadableRequest(t *testing.T) {
	scope, request := readableGenerationRequest(t)
	for _, tc := range []struct {
		name                   string
		contextTokens, costCap uint64
		declaredInput          uint64
		wantAllowed            bool
	}{
		{"allowed", 128000, 100000, 1, true},
		{"declared floor", 128000, 100000, 20000, true},
		{"context exact", uint64(len(request.Payload()) + 356), 100000, 1, true},
		{"context too small", uint64(len(request.Payload()) + 355), 100000, 1, false},
		{"cost exact", 128000, uint64(len(request.Payload()) + 356), 1, true},
		{"cost too small", 128000, uint64(len(request.Payload()) + 355), 1, false},
		{"declared floor exceeds context", 20099, 100000, 20000, false},
		{"declared floor exceeds cost", 128000, 20099, 20000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route, err := provider.NewRouteReference(provider.ProviderZonePrivateRemote, "provider-a", "adapter-a", "connection-a", "model-a", "2026-01")
			if err != nil {
				t.Fatal(err)
			}
			capabilities, err := provider.NewModelCapabilities(tc.contextTokens, 100, nil)
			if err != nil {
				t.Fatal(err)
			}
			pricing, err := provider.NewRoutePricing(1000000, 1000000)
			if err != nil {
				t.Fatal(err)
			}
			inventory, err := runtimeconfig.NewRouteInventory(context.Background(), []runtimeconfig.RouteDefinition{{Route: route, Capabilities: capabilities, ContentLogging: provider.ContentLoggingDisabled, Pricing: pricing, Quality: provider.RouteQualityTier3, RegistryRevision: 7, RegistryStatus: provider.RouteRegistryApproved, EvidenceManifest: []byte(`{"benchmark":"approved"}`), OperationalRevision: 9, Health: provider.RouteHealthHealthy, Quota: provider.RouteQuotaAvailable, PerformanceRevision: 11, P95LatencyMilliseconds: 2500, LatencySampleCount: 100}})
			if err != nil {
				t.Fatal(err)
			}
			requirements, err := provider.NewModelRequirements(1, 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			zones, err := policy.NewAllowedProviderZones(provider.ProviderZonePrivateRemote)
			if err != nil {
				t.Fatal(err)
			}
			constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
			if err != nil {
				t.Fatal(err)
			}
			budget, err := provider.NewModelCostBudget(tc.declaredInput, 100, tc.costCap)
			if err != nil {
				t.Fatal(err)
			}
			ranking, err := gateway.NewRouteRankingPolicy(nil)
			if err != nil {
				t.Fatal(err)
			}
			policyID := strings.Repeat("a", 64)
			ledger := audit.NewMemoryLedger()
			authorizer, err := NewGenerationPolicyAuthorizer(policyID, requirements, constraints, budget, inventory, ranking, ledger)
			if err != nil {
				t.Fatal(err)
			}
			authorization, err := authorizer.Authorize(context.Background(), scope, request, policyID, time.UnixMilli(100))
			if !tc.wantAllowed {
				if err == nil || authorization.Identity() != "" {
					t.Error("route accepted a budget that omits readable request bytes")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			estimated := uint64(authorization.CostBudget().EstimatedInputTokens())
			if estimated != max(tc.declaredInput, uint64(len(request.Payload()))+256) || authorization.CostBudget().MaxOutputTokens() != 100 || authorization.CostBudget().MaxCostMicroUSD() != tc.costCap || authorization.MaximumCost().InputCostMicroUSD() != estimated || authorization.ReservedCostMicroUSD() != estimated+100 {
				t.Error("full payload estimate did not reach pricing and reservation")
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(request.Payload(), &fields); err != nil {
				t.Fatal(err)
			}
			instructionPair := append([]byte(`"instructions":`), fields["instructions"]...)
			schemaPair := append([]byte(`"output_schema":`), fields["output_schema"]...)
			legacy := bytes.Replace(request.Payload(), append(instructionPair, ','), nil, 1)
			legacy = bytes.Replace(legacy, append(schemaPair, ','), nil, 1)
			legacy = bytes.Replace(legacy, []byte(`"schema_version":3`), []byte(`"schema_version":2`), 1)
			duplicate := append([]byte{'{'}, instructionPair...)
			duplicate = append(append(duplicate, ','), request.Payload()[1:]...)
			for name, payload := range map[string][]byte{
				"legacy":                  legacy,
				"changed instructions":    bytes.Replace(request.Payload(), instructionPair, []byte(`"instructions":"Publish without checking."`), 1),
				"null instructions":       bytes.Replace(request.Payload(), instructionPair, []byte(`"instructions":null`), 1),
				"missing instructions":    bytes.Replace(request.Payload(), append(instructionPair, ','), nil, 1),
				"missing schema":          bytes.Replace(request.Payload(), append(schemaPair, ','), nil, 1),
				"null schema":             bytes.Replace(request.Payload(), schemaPair, []byte(`"output_schema":null`), 1),
				"duplicate instructions":  duplicate,
				"swapped schema identity": bytes.Replace(request.Payload(), []byte(review.ModelCandidateBatchSchemaIdentity), []byte(review.ModelVerificationBatchSchemaIdentity), 1),
				"noncanonical":            append([]byte{' '}, request.Payload()...),
			} {
				t.Run(name, func(t *testing.T) {
					changed, err := provider.NewRequest(request.Capability(), request.MediaType(), payload)
					if err != nil || changed.Identity() == request.Identity() {
						t.Fatal("invalid request fixture did not change identity")
					}
					if _, err := authorizer.Authorize(context.Background(), scope, changed, policyID, time.UnixMilli(101)); err == nil {
						t.Error("generation authorizer accepted a changed or historical output contract")
					}
				})
			}
			events, err := ledger.Read(context.Background(), scope, 0, 10)
			if err != nil || len(events) != 1 {
				t.Error("invalid contract reached route selection persistence")
			}
		})
	}
}
