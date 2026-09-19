package openai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

func TestResponsesWireCarriesExactReadableReviewContracts(t *testing.T) {
	scope, err := audit.NewReviewScope("tenant", "repository", "run")
	if err != nil {
		t.Fatal(err)
	}
	memoryScope, err := memory.NewScope("tenant", "repository", "actor", memory.RefVisibilityExact, strings.Repeat("a", 64), []string{"src"})
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
	verification, err := review.NewVerificationRequestContext(generationRequest.Payload(), generation.Identity(), scope.Identity(), generation.MemoryScopeIdentity(), generation.MemoryIdentity(), snapshot, generation.EvidenceItems(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	verificationRequest, err := verification.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	credentials := &credentialProvider{key: testKey(t)}
	adapter := newTestAdapter(t, "http://127.0.0.1:8080/v1", credentials)
	for _, tc := range []struct {
		name                 string
		request              provider.Request
		schemaPath, identity string
	}{
		{"candidate", generationRequest, "../../../schemas/review/model-candidate-batch-v1.schema.json", review.ModelCandidateBatchSchemaIdentity},
		{"verifier", verificationRequest, "../../../schemas/review/model-verification-batch-v1.schema.json", review.ModelVerificationBatchSchemaIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := adapter.newRequest(context.Background(), testKey(t), "pinned-model-version", 4096, tc.request.Payload())
			if err != nil {
				t.Fatal(err)
			}
			defer request.Body.Close()
			encoded, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			var wire requestWire
			if err := json.Unmarshal(encoded, &wire); err != nil {
				t.Fatal(err)
			}
			if wire.Store || wire.Model != "pinned-model-version" || wire.MaxOutputTokens != 4096 || len(wire.Input) != 1 || len(wire.Input[0].Content) != 1 {
				t.Fatal("wire changed model, output bound, storage, or message count")
			}
			if !bytes.Equal([]byte(wire.Input[0].Content[0].Text), tc.request.Payload()) {
				t.Fatal("wire text differs from the identity-bound payload")
			}
			var contract struct {
				Instructions   string         `json:"instructions"`
				Schema         map[string]any `json:"output_schema"`
				SchemaIdentity string         `json:"output_schema_identity"`
			}
			if err := json.Unmarshal([]byte(wire.Input[0].Content[0].Text), &contract); err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(contract.Instructions) == "" || contract.Schema == nil || contract.SchemaIdentity != tc.identity {
				t.Fatal("actual HTTP body lacks the readable host output contract")
			}
			publicBytes, err := os.ReadFile(tc.schemaPath)
			if err != nil {
				t.Fatal(err)
			}
			var public any
			if err := json.Unmarshal(publicBytes, &public); err != nil {
				t.Fatal(err)
			}
			publicCanonical, err := json.Marshal(public)
			if err != nil {
				t.Fatal(err)
			}
			sentCanonical, err := json.Marshal(contract.Schema)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(sentCanonical)
			if !bytes.Equal(sentCanonical, publicCanonical) || hex.EncodeToString(digest[:]) != tc.identity {
				t.Fatal("wire schema differs from the full public schema")
			}
		})
	}
	if credentials.calls.Load() != 0 {
		t.Fatal("request serialization retrieved credentials")
	}
}
