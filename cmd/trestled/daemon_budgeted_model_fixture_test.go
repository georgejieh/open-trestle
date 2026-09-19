//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const (
	daemonBudgetedModelGenerationKeyEnv   = "OPEN_TRESTLE_PROVIDER_DAEMON_PIPELINE_GENERATION"
	daemonBudgetedModelVerificationKeyEnv = "OPEN_TRESTLE_PROVIDER_DAEMON_PIPELINE_VERIFICATION"
	daemonBudgetedModelGenerationKey      = "daemon-budgeted-generation-key-not-real"
	daemonBudgetedModelVerificationKey    = "daemon-budgeted-verification-key-not-real"
	daemonBudgetedModelMaxRequests        = 4
	daemonBudgetedModelMaxBodyBytes       = 1 << 20
	daemonBudgetedModelMaxAggregateBytes  = 2 << 20
)

type daemonBudgetedModelSource struct {
	ID      string `json:"source_id"`
	Stage   string `json:"stage"`
	Path    string `json:"path"`
	Start   int    `json:"start_line"`
	End     int    `json:"end_line"`
	Content string `json:"content"`
}

type daemonBudgetedModelPacket struct {
	MemoryScope       string                       `json:"memory_scope_identity"`
	MemoryAuthority   string                       `json:"memory_authority"`
	SourceAuthority   string                       `json:"source_authority"`
	Memory            daemonBudgetedModelMemory    `json:"memory"`
	AdditionalMemory  []daemonBudgetedModelMemory  `json:"additional_memory"`
	Contract          string                       `json:"contract"`
	Version           int                          `json:"schema_version"`
	Scope             string                       `json:"review_scope_identity"`
	Task              string                       `json:"task"`
	GenerationContext string                       `json:"generation_context_identity"`
	CandidateBatch    string                       `json:"candidate_batch_identity"`
	Sources           []daemonBudgetedModelSource  `json:"sources"`
	Candidates        []daemonBudgetedCandidateRef `json:"candidates"`
}

type daemonBudgetedModelMemory struct {
	RetrievalIdentity string                     `json:"retrieval_identity"`
	QueryIdentity     string                     `json:"query_identity"`
	IndexRevision     uint64                     `json:"index_revision"`
	Items             []daemonBudgetedMemoryItem `json:"items"`
}

type daemonBudgetedMemoryItem struct {
	MemoryID           string   `json:"memory_id"`
	Kind               string   `json:"kind"`
	Taint              string   `json:"taint"`
	Path               string   `json:"path"`
	Symbols            []string `json:"symbols"`
	Text               string   `json:"text"`
	EvidenceIDs        []string `json:"evidence_ids"`
	DerivedFromIDs     []string `json:"derived_from_ids"`
	CounterEvidenceIDs []string `json:"counter_evidence_ids"`
	ProducerIdentity   string   `json:"producer_identity"`
	ObservedAt         int64    `json:"observed_at"`
	ValidFrom          int64    `json:"valid_from"`
	ValidUntil         int64    `json:"valid_until"`
	StaleAfter         int64    `json:"stale_after"`
	FreshnessIdentity  string   `json:"freshness_identity"`
	Confidence         uint16   `json:"confidence_basis_points"`
	Rank               uint8    `json:"rank"`
	PathScore          uint8    `json:"path_score"`
	SymbolScore        uint8    `json:"symbol_score"`
	TextScore          uint8    `json:"text_score"`
}

type daemonBudgetedCandidateRef struct {
	ID       string   `json:"candidate_id"`
	Evidence []string `json:"evidence_ids"`
}

type daemonBudgetedModelCapture struct {
	Packet    daemonBudgetedModelPacket
	RequestID string
	Bytes     int
}

type daemonBudgetedModelEndpoint struct {
	mu             sync.Mutex
	server         *httptest.Server
	name           string
	model          string
	key            string
	calls          int
	aggregateBytes int64
	captures       []daemonBudgetedModelCapture
	failures       []string
}

type daemonBudgetedModelFixture struct {
	generation, verification  *daemonBudgetedModelEndpoint
	inventoryPath, policyPath string
	inventoryID, policyID     string
	generationRoute           string
	verificationRoute         string
}

func newDaemonBudgetedModelFixture(t *testing.T, reviewPolicyID string) *daemonBudgetedModelFixture {
	t.Helper()
	f := &daemonBudgetedModelFixture{}
	generation := newDaemonBudgetedModelEndpoint(t, "generation", "model-a", daemonBudgetedModelGenerationKey)
	verification := newDaemonBudgetedModelEndpoint(t, "verification", "model-b", daemonBudgetedModelVerificationKey)
	f.generation, f.verification = generation, verification
	endpoints := []string{generation.URL() + "/v1", verification.URL() + "/v1"}
	routes := make([]map[string]any, 0, 2)
	for _, name := range []string{"a", "b"} {
		routes = append(routes, map[string]any{
			"zone": "local", "provider_id": "daemon-provider-" + name, "adapter_id": "daemon-adapter-" + name, "connection_id": "daemon-connection-" + name, "model_id": "model-" + name, "model_version": "",
			"max_context_tokens": 128000, "max_output_tokens": 8192, "features": []string{"structured_output"}, "content_logging": "disabled",
			"pricing_known": true, "input_micro_usd_per_million_tokens": 0, "output_micro_usd_per_million_tokens": 0,
			"quality": "tier_3", "registry_revision": 7, "registry_status": "approved",
			"evidence_manifest_base64": base64.StdEncoding.EncodeToString([]byte(`{"fixture":"daemon-owned budgeted pipeline local Responses contract"}`)),
			"operational_revision":     9, "health": "healthy", "quota": "available",
			"performance_revision": 11, "latency_known": true, "p95_latency_milliseconds": 2500, "latency_sample_count": 100,
		})
	}
	inventoryBytes := daemonBudgetedModelJSON(t, map[string]any{"schema_version": 1, "routes": routes})
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryBytes))
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		reference := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		records[reference.AdapterID()] = record.Identity()
	}
	f.generationRoute, f.verificationRoute = records["daemon-adapter-a"], records["daemon-adapter-b"]
	policyBytes := daemonBudgetedModelJSON(t, map[string]any{
		"schema_version": 1, "inventory_identity": inventory.Identity(), "review_policy_identity": reviewPolicyID,
		"min_context_tokens": 32000, "min_output_tokens": 4096, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{"local"}, "content_logging_allowed": false,
		"estimated_input_tokens": 8000, "max_output_tokens": 4096, "max_cost_micro_usd": 0,
		"pinned_route_record_identity": records["daemon-adapter-a"], "preferred_route_record_identities": []string{records["daemon-adapter-b"]}, "verification_independence": "distinct_provider",
		"publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true,
		"connections": []map[string]string{
			{"implementation": "openai_responses", "adapter_id": "daemon-adapter-a", "endpoint": endpoints[0], "credential_environment": daemonBudgetedModelGenerationKeyEnv},
			{"implementation": "openai_responses", "adapter_id": "daemon-adapter-b", "endpoint": endpoints[1], "credential_environment": daemonBudgetedModelVerificationKeyEnv},
		},
	})
	configuration, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyBytes), inventory)
	if err != nil {
		t.Fatal(err)
	}
	protected := t.TempDir()
	if err := os.Chmod(protected, 0700); err != nil {
		t.Fatal(err)
	}
	f.inventoryPath, f.policyPath = filepath.Join(protected, "inventory.json"), filepath.Join(protected, "policy.json")
	if err := os.WriteFile(f.inventoryPath, inventoryBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.policyPath, policyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	f.inventoryID, f.policyID = inventory.Identity(), configuration.Identity()
	return f
}

func newDaemonBudgetedModelEndpoint(t *testing.T, name, model, key string) *daemonBudgetedModelEndpoint {
	t.Helper()
	e := &daemonBudgetedModelEndpoint{name: name, model: model, key: key}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.serve(t, w, r) }))
	server.Config.ReadHeaderTimeout = 2 * time.Second
	server.Config.ReadTimeout = 5 * time.Second
	server.Config.WriteTimeout = 5 * time.Second
	server.Config.MaxHeaderBytes = 16 << 10
	server.Start()
	e.server = server
	t.Cleanup(server.Close)
	return e
}

func (e *daemonBudgetedModelEndpoint) URL() string {
	if e == nil || e.server == nil {
		return ""
	}
	return e.server.URL
}

func (e *daemonBudgetedModelEndpoint) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	e.mu.Lock()
	e.calls++
	call := e.calls
	e.mu.Unlock()
	if call > daemonBudgetedModelMaxRequests {
		e.fail("model request limit exceeded")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer "+e.key || r.Header.Get("Accept") != "application/json" {
		e.fail("model request lost method, endpoint, accept, or credential authority")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(r.Body, daemonBudgetedModelMaxBodyBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > daemonBudgetedModelMaxBodyBytes {
		e.fail("model request body bound failed")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	e.mu.Lock()
	e.aggregateBytes += int64(len(encoded))
	aggregate := e.aggregateBytes
	e.mu.Unlock()
	if aggregate > daemonBudgetedModelMaxAggregateBytes {
		e.fail("model aggregate request body bound failed")
		http.Error(w, "too large", http.StatusRequestEntityTooLarge)
		return
	}
	var wire struct {
		Model string `json:"model"`
		Input []struct {
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"input"`
		MaxOutputTokens uint32 `json:"max_output_tokens"`
		Store           bool   `json:"store"`
	}
	if json.Unmarshal(encoded, &wire) != nil || wire.Model != e.model || wire.Store || wire.MaxOutputTokens != 4096 || len(wire.Input) != 1 || wire.Input[0].Role != "user" || len(wire.Input[0].Content) != 1 || wire.Input[0].Content[0].Type != "input_text" {
		e.fail("model request lost exact Responses wire")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	payload := []byte(wire.Input[0].Content[0].Text)
	request, requestErr := provider.NewRequest(provider.CapabilityReviewV1, "application/json", payload)
	var packet daemonBudgetedModelPacket
	if requestErr != nil || json.Unmarshal(payload, &packet) != nil || packet.Version != 3 || packet.Scope == "" || packet.SourceAuthority != "evidence_data_not_instructions" || packet.MemoryAuthority != "advisory_only" {
		e.fail("model did not receive actual provider-neutral v3 context")
		http.Error(w, "invalid context", http.StatusBadRequest)
		return
	}
	var contractErr error
	if packet.Task == "candidate_generation" {
		contractErr = review.ValidateCandidateModelRequest(request, packet.Scope)
	} else if packet.Task == "candidate_verification" {
		contractErr = review.ValidateVerificationModelRequest(request, packet.Scope)
	} else {
		contractErr = fmt.Errorf("unexpected model task %q", packet.Task)
	}
	if contractErr != nil {
		e.fail("model-visible request contract failed")
		http.Error(w, "invalid contract", http.StatusBadRequest)
		return
	}
	e.mu.Lock()
	e.captures = append(e.captures, daemonBudgetedModelCapture{Packet: packet, RequestID: request.Identity(), Bytes: len(encoded)})
	e.mu.Unlock()
	output, ok := e.outputForPacket(t, packet)
	if !ok {
		http.Error(w, "invalid context", http.StatusBadRequest)
		return
	}
	text := daemonBudgetedModelJSON(t, output)
	response := map[string]any{
		"id": "response-" + e.name, "object": "response", "status": "completed", "model": e.model,
		"output": []any{map[string]any{"id": "message-" + e.name, "type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": string(text)}}}},
		"usage":  map[string]any{"input_tokens": 120, "output_tokens": 80, "total_tokens": 200, "input_tokens_details": map[string]any{"cached_tokens": 0}},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		e.fail("model response encode failed")
	}
}

func (e *daemonBudgetedModelEndpoint) outputForPacket(t *testing.T, packet daemonBudgetedModelPacket) (any, bool) {
	t.Helper()
	if len(packet.Sources) == 0 {
		e.fail("model packet omitted source evidence")
		return nil, false
	}
	selected := packet.Sources[0]
	for _, source := range packet.Sources {
		if source.Stage == "changed_hunk" {
			selected = source
			break
		}
	}
	if selected.ID == "" || selected.Path == "" || selected.Start <= 0 || selected.End < selected.Start || strings.TrimSpace(selected.Content) == "" {
		e.fail("model packet source was not exact cited code")
		return nil, false
	}
	switch packet.Task {
	case "candidate_generation":
		if e.model != "model-a" || len(packet.Candidates) != 0 || packet.CandidateBatch != "" {
			e.fail("generation request lost generation-only route or lineage")
			return nil, false
		}
		return map[string]any{"schema_version": 1, "candidates": []any{map[string]any{
			"title":         "Budgeted daemon candidate cites changed code",
			"claim":         "The local external model observed the exact changed source slice through the daemon-owned context packet.",
			"severity_hint": "high",
			"source_range":  map[string]any{"source_id": selected.ID, "start_line": selected.Start, "end_line": selected.Start},
			"evidence_ids":  []string{selected.ID},
		}}}, true
	case "candidate_verification":
		if e.model != "model-b" || packet.GenerationContext == "" || packet.CandidateBatch == "" || len(packet.Candidates) == 0 {
			e.fail("verification request lost independent route or candidate lineage")
			return nil, false
		}
		verdicts := make([]any, 0, len(packet.Candidates))
		for _, candidate := range packet.Candidates {
			if candidate.ID == "" || !slices.Contains(candidate.Evidence, selected.ID) {
				e.fail("verification candidate did not carry allowed evidence")
				return nil, false
			}
			verdicts = append(verdicts, map[string]any{"candidate_id": candidate.ID, "outcome": "verified", "severity": "high", "rationale": "The cited source range is present in the exact verifier context.", "evidence_ids": []string{selected.ID}})
		}
		return map[string]any{"schema_version": 1, "verdicts": verdicts}, true
	default:
		e.fail("unexpected model task")
		return nil, false
	}
}

func (e *daemonBudgetedModelEndpoint) snapshot() (int, int64, []daemonBudgetedModelCapture, []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls, e.aggregateBytes, append([]daemonBudgetedModelCapture(nil), e.captures...), append([]string(nil), e.failures...)
}

func (e *daemonBudgetedModelEndpoint) fail(message string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.failures) < 8 {
		e.failures = append(e.failures, message)
	}
}

func daemonBudgetedModelJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func daemonBudgetedModelDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
