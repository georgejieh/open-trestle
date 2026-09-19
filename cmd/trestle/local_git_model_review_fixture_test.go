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

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const localModelSecret = "LOCAL_MODEL_SOURCE_SENTINEL_9741"
const localModelKey = "local-test-key-not-a-real-credential"

type localModelSource struct {
	ID      string `json:"source_id"`
	Stage   string `json:"stage"`
	Path    string `json:"path"`
	Start   int    `json:"start_line"`
	End     int    `json:"end_line"`
	Content string `json:"content"`
}

type localModelPacket struct {
	MemoryScope      string             `json:"memory_scope_identity"`
	MemoryAuthority  string             `json:"memory_authority"`
	SourceAuthority  string             `json:"source_authority"`
	Memory           localModelMemory   `json:"memory"`
	AdditionalMemory []localModelMemory `json:"additional_memory"`

	Contract          string             `json:"contract"`
	Version           int                `json:"schema_version"`
	Scope             string             `json:"review_scope_identity"`
	Task              string             `json:"task"`
	GenerationContext string             `json:"generation_context_identity"`
	CandidateBatch    string             `json:"candidate_batch_identity"`
	Sources           []localModelSource `json:"sources"`
	Candidates        []struct {
		ID       string   `json:"candidate_id"`
		Evidence []string `json:"evidence_ids"`
	} `json:"candidates"`
}

type localModelMemory struct {
	RetrievalIdentity string                 `json:"retrieval_identity"`
	QueryIdentity     string                 `json:"query_identity"`
	IndexRevision     uint64                 `json:"index_revision"`
	Items             []localModelMemoryItem `json:"items"`
}

type localModelMemoryItem struct {
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

type localModelCapture struct {
	Packet    localModelPacket
	ContextID string
	RequestID string
}

type localModelEndpoint struct {
	mu         sync.Mutex
	calls      int
	captures   []localModelCapture
	mode       string
	model      string
	entered    chan struct{}
	canceled   chan struct{}
	stop       chan struct{}
	enterOnce  sync.Once
	cancelOnce sync.Once
}

func (m *localModelEndpoint) snapshot() (int, []localModelCapture) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls, append([]localModelCapture(nil), m.captures...)
}

func localModelDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func localModelJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (m *localModelEndpoint) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	if r.Method != http.MethodPost || r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer "+localModelKey {
		t.Error("model transport lost endpoint, method, or test credential binding")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(r.Body, (8<<20)+1))
	if err != nil || len(encoded) > 8<<20 {
		t.Error("unbounded model request")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var wire struct {
		Model     string `json:"model"`
		Store     bool   `json:"store"`
		MaxOutput uint32 `json:"max_output_tokens"`
		Input     []struct {
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"input"`
	}
	if json.Unmarshal(encoded, &wire) != nil || wire.Model != m.model || wire.Store || wire.MaxOutput != 4096 || len(wire.Input) != 1 || wire.Input[0].Role != "user" || len(wire.Input[0].Content) != 1 || wire.Input[0].Content[0].Type != "input_text" {
		t.Error("model request lost exact bounded Responses wire")
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	payload := []byte(wire.Input[0].Content[0].Text)
	var packet localModelPacket
	request, requestErr := provider.NewRequest(provider.CapabilityReviewV1, "application/json", payload)
	if json.Unmarshal(payload, &packet) != nil || requestErr != nil || packet.Version != 3 {
		t.Error("model did not receive the actual v3 context")
		http.Error(w, "invalid context", http.StatusBadRequest)
		return
	}
	if packet.Task == "candidate_generation" {
		err = review.ValidateCandidateModelRequest(request, packet.Scope)
	} else if packet.Task == "candidate_verification" {
		err = review.ValidateVerificationModelRequest(request, packet.Scope)
	} else {
		err = fmt.Errorf("unexpected model task")
	}
	if err != nil {
		t.Error("model-visible instructions, schema, or authority do not match the host contract")
		http.Error(w, "invalid contract", http.StatusBadRequest)
		return
	}
	m.mu.Lock()
	m.captures = append(m.captures, localModelCapture{packet, localModelDigest(payload), request.Identity()})
	m.mu.Unlock()
	m.enterOnce.Do(func() { close(m.entered) })
	if m.mode == "wait" {
		select {
		case <-r.Context().Done():
			m.cancelOnce.Do(func() { close(m.canceled) })
		case <-m.stop:
		}
		return
	}

	var changed, caller localModelSource
	for _, source := range packet.Sources {
		if source.Path == "a.go" {
			changed = source
		}
		if source.Path == "caller.go" {
			caller = source
		}
	}
	if changed.ID == "" || caller.ID == "" || changed.Stage != "changed_hunk" || caller.Stage != "direct_reference" || !strings.Contains(changed.Content, "return 10 / x") || !strings.Contains(caller.Content, "Changed(0)") || changed.Start > 2 || changed.End < 2 {
		t.Error("source-to-model path omitted exact changed code or its unchanged caller")
		http.Error(w, "missing source", http.StatusBadRequest)
		return
	}
	evidenceIDs := []string{changed.ID, caller.ID}
	var result any
	switch packet.Task {
	case "candidate_generation":
		if m.model != "model-a" || len(packet.Candidates) != 0 {
			t.Error("generation did not use its pinned independent route")
		}
		candidates := []any{}
		if m.mode != "empty" {
			candidates = append(candidates, map[string]any{
				"title": "Zero-valued caller now panics", "claim": "Consume passes zero to Changed after removal of the division guard.", "severity_hint": "high",
				"source_range": map[string]any{"source_id": changed.ID, "start_line": 2, "end_line": 2}, "evidence_ids": evidenceIDs,
			})
		}
		result = map[string]any{"schema_version": 1, "candidates": candidates}
	case "candidate_verification":
		if m.model != "model-b" || packet.GenerationContext == "" || packet.CandidateBatch == "" {
			t.Error("verification lost independent provider or generation lineage")
		}
		verdicts := []any{}
		for _, candidate := range packet.Candidates {
			if candidate.ID == "" || !slices.Contains(candidate.Evidence, changed.ID) || !slices.Contains(candidate.Evidence, caller.ID) {
				t.Error("verification did not receive actual candidate/evidence identities")
			}
			outcome, severity := "verified", "high"
			if m.mode == "inconclusive" {
				outcome, severity = "inconclusive", "none"
			}
			id := candidate.ID
			if m.mode == "wrong_candidate" {
				id = strings.Repeat("f", 64)
			}
			verdicts = append(verdicts, map[string]any{"candidate_id": id, "outcome": outcome, "severity": severity, "rationale": "The cited caller passes zero to the unguarded integer division.", "evidence_ids": evidenceIDs})
		}
		result = map[string]any{"schema_version": 1, "verdicts": verdicts}
	}
	text, err := json.Marshal(result)
	if err != nil {
		t.Error(err)
		return
	}
	if m.mode == "malformed" {
		text = []byte(`{"schema_version":1,"candidates":[`)
	}
	response := map[string]any{
		"id": "response-" + m.model, "object": "response", "status": "completed", "model": m.model,
		"output": []any{map[string]any{"id": "message-" + m.model, "type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": string(text)}}}},
		"usage":  map[string]any{"input_tokens": 100, "output_tokens": 100, "total_tokens": 200},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		t.Error(err)
	}
}

type localModelFixture struct {
	args                               []string
	objects, base, head                string
	inventoryPath, policyPath          string
	inventoryID, policyID              string
	generationRoute, verificationRoute string
	generation, verification           *localModelEndpoint
}

type localModelFixtureOptions struct {
	generationMode, verificationMode                      string
	verifierPending, remote, expensive, capacity, partial bool
}

func newLocalModelFixture(t *testing.T, options localModelFixtureOptions) *localModelFixture {
	t.Helper()
	f := &localModelFixture{}
	endpoints := make([]string, 0, 2)
	for i, mode := range []string{options.generationMode, options.verificationMode} {
		name := []string{"a", "b"}[i]
		endpoint := &localModelEndpoint{mode: mode, model: "model-" + name, entered: make(chan struct{}), canceled: make(chan struct{}), stop: make(chan struct{})}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { endpoint.serve(t, w, r) }))
		t.Cleanup(func() { close(endpoint.stop); server.Close() })
		endpoints = append(endpoints, server.URL+"/v1")
		if i == 0 {
			f.generation = endpoint
		} else {
			f.verification = endpoint
		}
	}
	t.Setenv("OPEN_TRESTLE_PROVIDER_LOCAL_TEST_A", localModelKey)
	t.Setenv("OPEN_TRESTLE_PROVIDER_LOCAL_TEST_B", localModelKey)
	base := map[string][]byte{
		"a.go":      []byte("package p\nfunc Changed(x int) int { if x == 0 { return 0 }; return 10 / x }\n// " + localModelSecret + "\n"),
		"caller.go": []byte("package p\nfunc Consume() int { return Changed(0) }\n"),
	}
	head := map[string][]byte{
		"a.go":      []byte("package p\nfunc Changed(x int) int { return 10 / x }\n// " + localModelSecret + "\n"),
		"caller.go": base["caller.go"],
	}
	if options.partial {
		base["removed.go"] = []byte("package p\n")
	}
	f.objects, f.base, f.head = writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, base, head)
	zone := provider.ProviderZoneLocal
	if options.remote {
		zone = provider.ProviderZonePrivateRemote
		endpoints = []string{"https://provider-a.invalid/v1", "https://provider-b.invalid/v1"}
	}
	routes := make([]map[string]any, 0, 2)
	for i, name := range []string{"a", "b"} {
		status := provider.RouteRegistryApproved
		if i == 1 && options.verifierPending {
			status = provider.RouteRegistryPending
		}
		contextTokens := uint64(128000)
		outputTokens := uint64(8192)
		if options.capacity {
			contextTokens = 5000
			outputTokens = 4096
		}
		price := uint64(0)
		if options.expensive {
			price = 1000000
		}
		routes = append(routes, map[string]any{
			"zone": zone.String(), "provider_id": "provider-" + name, "adapter_id": "adapter-" + name, "connection_id": "connection-" + name, "model_id": "model-" + name, "model_version": "",
			"max_context_tokens": contextTokens, "max_output_tokens": outputTokens, "features": []string{"structured_output"}, "content_logging": provider.ContentLoggingDisabled.String(),
			"pricing_known": true, "input_micro_usd_per_million_tokens": price, "output_micro_usd_per_million_tokens": price,
			"quality": provider.RouteQualityTier3.String(), "registry_revision": 7, "registry_status": status.String(),
			"evidence_manifest_base64": base64.StdEncoding.EncodeToString([]byte(`{"fixture":"operator-approved local Responses contract"}`)),
			"operational_revision":     9, "health": provider.RouteHealthHealthy.String(), "quota": provider.RouteQuotaAvailable.String(),
			"performance_revision": 11, "latency_known": true, "p95_latency_milliseconds": 2500, "latency_sample_count": 100,
		})
	}
	inventoryBytes := localModelJSON(t, map[string]any{"schema_version": 1, "routes": routes})
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryBytes))
	if err != nil {
		t.Fatal(err)
	}
	records := map[string]string{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		records[record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = record.Identity()
	}
	f.generationRoute, f.verificationRoute = records["adapter-a"], records["adapter-b"]
	policyBytes := localModelJSON(t, map[string]any{
		"schema_version": 1, "inventory_identity": inventory.Identity(), "review_policy_identity": localModelDigest([]byte("local-review-policy")),
		"min_context_tokens": 1, "min_output_tokens": 1, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{zone.String()}, "content_logging_allowed": false,
		"estimated_input_tokens": 1, "max_output_tokens": 4096, "max_cost_micro_usd": 0,
		"pinned_route_record_identity": records["adapter-a"], "preferred_route_record_identities": []string{records["adapter-b"]}, "verification_independence": "distinct_provider",
		"publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_provider", "publication_block_on_inconclusive": true,
		"connections": []map[string]string{
			{"implementation": "openai_responses", "adapter_id": "adapter-a", "endpoint": endpoints[0], "credential_environment": "OPEN_TRESTLE_PROVIDER_LOCAL_TEST_A"},
			{"implementation": "openai_responses", "adapter_id": "adapter-b", "endpoint": endpoints[1], "credential_environment": "OPEN_TRESTLE_PROVIDER_LOCAL_TEST_B"},
		},
	})
	configuration, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(policyBytes), inventory)
	if err != nil {
		t.Fatal(err)
	}
	f.inventoryID, f.policyID = inventory.Identity(), configuration.Identity()
	protected := t.TempDir()
	if err := os.Chmod(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	f.inventoryPath, f.policyPath = filepath.Join(protected, "inventory.json"), filepath.Join(protected, "policy.json")
	if err := os.WriteFile(f.inventoryPath, inventoryBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.policyPath, policyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	f.args = append([]string{"local-git", "model-review"}, localGitChangeArgs(f.objects, evidence.RevisionAlgorithmSHA1, f.base, f.head)...)
	f.args = append(f.args, "--tenant", "tenant-local", "--repository", "repository-local", "--route-inventory", f.inventoryPath, "--runtime-policy", f.policyPath, "--egress", "local-only", "--timeout", "5s", "--format", "json")
	return f
}
