package localreview

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const rmModelSecret = "LOCAL_MODEL_SOURCE_SENTINEL_9741"
const rmModelKey = "local-test-key-not-a-real-credential"

type rmModelSource struct {
	ID      string `json:"source_id"`
	Stage   string `json:"stage"`
	Path    string `json:"path"`
	Start   int    `json:"start_line"`
	End     int    `json:"end_line"`
	Content string `json:"content"`
}

type rmModelPacket struct {
	MemoryScope      string          `json:"memory_scope_identity"`
	MemoryAuthority  string          `json:"memory_authority"`
	SourceAuthority  string          `json:"source_authority"`
	Memory           rmModelMemory   `json:"memory"`
	AdditionalMemory []rmModelMemory `json:"additional_memory"`

	Contract          string          `json:"contract"`
	Version           int             `json:"schema_version"`
	Scope             string          `json:"review_scope_identity"`
	Task              string          `json:"task"`
	GenerationContext string          `json:"generation_context_identity"`
	CandidateBatch    string          `json:"candidate_batch_identity"`
	Sources           []rmModelSource `json:"sources"`
	Candidates        []struct {
		ID       string   `json:"candidate_id"`
		Evidence []string `json:"evidence_ids"`
	} `json:"candidates"`
}

type rmModelMemory struct {
	RetrievalIdentity string              `json:"retrieval_identity"`
	QueryIdentity     string              `json:"query_identity"`
	IndexRevision     uint64              `json:"index_revision"`
	Items             []rmModelMemoryItem `json:"items"`
}

type rmModelMemoryItem struct {
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

type rmModelCapture struct {
	Packet    rmModelPacket
	ContextID string
	RequestID string
}

type rmModelEndpoint struct {
	mu         sync.Mutex
	calls      int
	captures   []rmModelCapture
	mode       string
	model      string
	entered    chan struct{}
	canceled   chan struct{}
	stop       chan struct{}
	enterOnce  sync.Once
	cancelOnce sync.Once
}

func (m *rmModelEndpoint) snapshot() (int, []rmModelCapture) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls, append([]rmModelCapture(nil), m.captures...)
}

func rmModelDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func rmModelJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (m *rmModelEndpoint) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	if r.Method != http.MethodPost || r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer "+rmModelKey {
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
	var packet rmModelPacket
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
	m.captures = append(m.captures, rmModelCapture{packet, rmModelDigest(payload), request.Identity()})
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

	var changed, caller rmModelSource
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

type rmModelFixture struct {
	args                               []string
	objects, base, head                string
	inventoryPath, policyPath          string
	inventoryID, policyID              string
	generationRoute, verificationRoute string
	generation, verification           *rmModelEndpoint
}

type rmModelFixtureOptions struct {
	generationMode, verificationMode                      string
	verifierPending, remote, expensive, capacity, partial bool
}

func newRmModelFixture(t *testing.T, options rmModelFixtureOptions) *rmModelFixture {
	t.Helper()
	f := &rmModelFixture{}
	endpoints := make([]string, 0, 2)
	for i, mode := range []string{options.generationMode, options.verificationMode} {
		name := []string{"a", "b"}[i]
		endpoint := &rmModelEndpoint{mode: mode, model: "model-" + name, entered: make(chan struct{}), canceled: make(chan struct{}), stop: make(chan struct{})}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { endpoint.serve(t, w, r) }))
		t.Cleanup(func() { close(endpoint.stop); server.Close() })
		endpoints = append(endpoints, server.URL+"/v1")
		if i == 0 {
			f.generation = endpoint
		} else {
			f.verification = endpoint
		}
	}
	base := map[string][]byte{
		"a.go":      []byte("package p\nfunc Changed(x int) int { if x == 0 { return 0 }; return 10 / x }\n// " + rmModelSecret + "\n"),
		"caller.go": []byte("package p\nfunc Consume() int { return Changed(0) }\n"),
	}
	head := map[string][]byte{
		"a.go":      []byte("package p\nfunc Changed(x int) int { return 10 / x }\n// " + rmModelSecret + "\n"),
		"caller.go": base["caller.go"],
	}
	if options.partial {
		base["removed.go"] = []byte("package p\n")
	}
	f.objects, f.base, f.head = rmWriteGit(t, evidence.RevisionAlgorithmSHA1, base, head)
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
	inventoryBytes := rmModelJSON(t, map[string]any{"schema_version": 1, "routes": routes})
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
	policyBytes := rmModelJSON(t, map[string]any{
		"schema_version": 1, "inventory_identity": inventory.Identity(), "review_policy_identity": rmModelDigest([]byte("local-review-policy")),
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
	return f
}

func rmWriteGit(t *testing.T, algorithm evidence.RevisionAlgorithm, baseContents, headContents map[string][]byte) (string, string, string) {
	t.Helper()
	objects := t.TempDir()
	baseTree := rmWriteTree(t, objects, algorithm, baseContents)
	headTree := rmWriteTree(t, objects, algorithm, headContents)
	baseCommit := []byte("tree " + baseTree + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nbase\n")
	headCommit := []byte("tree " + headTree + "\nauthor A <a@example.com> 0 +0000\ncommitter A <a@example.com> 0 +0000\n\nhead\n")
	return objects, rmWriteObject(t, objects, algorithm, "commit", baseCommit), rmWriteObject(t, objects, algorithm, "commit", headCommit)
}

func rmWriteTree(t *testing.T, objects string, algorithm evidence.RevisionAlgorithm, contents map[string][]byte) string {
	t.Helper()
	paths := make([]string, 0, len(contents))
	for path := range contents {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var tree []byte
	for _, path := range paths {
		blob := rmWriteObject(t, objects, algorithm, "blob", contents[path])
		tree = append(tree, rmTreeEntry(t, "100644", path, blob)...)
	}
	return rmWriteObject(t, objects, algorithm, "tree", tree)
}

func rmTreeEntry(t *testing.T, mode, name, digest string) []byte {
	t.Helper()
	object, err := hex.DecodeString(digest)
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte(mode+" "+name), 0), object...)
}

func rmWriteObject(t *testing.T, objects string, algorithm evidence.RevisionAlgorithm, kind string, payload []byte) string {
	t.Helper()
	framed := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(payload))), payload...)
	var digest string
	if algorithm == evidence.RevisionAlgorithmSHA1 {
		sum := sha1.Sum(framed)
		digest = hex.EncodeToString(sum[:])
	} else {
		sum := sha256.Sum256(framed)
		digest = hex.EncodeToString(sum[:])
	}
	dir := filepath.Join(objects, digest[:2])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(dir, digest[2:]))
	if err != nil {
		t.Fatal(err)
	}
	zw := zlib.NewWriter(file)
	if _, err := zw.Write(framed); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return digest
}

const rmProducer = "084b41a50cddd2b3b18c829c2092fcabfbf003bc58c4f4202361b82a8e46327f"
const rmAdvice = "RETAINED_ADVISORY_SENTINEL: operator recalls zero-input contract; verify the actual changed source."

type rmScopeWire struct {
	Identity   string   `json:"identity"`
	Tenant     string   `json:"tenant_id"`
	Repository string   `json:"repository_id"`
	Actor      string   `json:"actor_id"`
	Visibility string   `json:"ref_visibility"`
	RefSet     string   `json:"ref_set_identity"`
	Prefixes   []string `json:"path_prefixes"`
}

type rmHeadWire struct {
	Kind      string `json:"kind"`
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
	Identity  string `json:"identity"`
}

type rmRecordWire struct {
	Identity string   `json:"record_identity"`
	Kind     string   `json:"kind"`
	Taint    string   `json:"taint"`
	Path     string   `json:"path"`
	Symbols  []string `json:"symbols"`
	Text     string   `json:"text"`
	Evidence []string `json:"evidence_ids"`
	Producer string   `json:"producer_identity"`
	Observed int64    `json:"observed_at"`
	From     int64    `json:"valid_from"`
	Until    int64    `json:"valid_until"`
}

type rmEnvelopeWire struct {
	Contract    string         `json:"contract"`
	Version     int            `json:"schema_version"`
	Attestation string         `json:"attestation"`
	Scope       rmScopeWire    `json:"scope"`
	Repository  string         `json:"repository_identity"`
	Head        rmHeadWire     `json:"head_revision"`
	Policy      string         `json:"runtime_policy_identity"`
	Paths       []string       `json:"allowed_paths"`
	Records     []rmRecordWire `json:"records"`
}

func rmJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func rmHash(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func rmHeadBytes(t *testing.T, w rmHeadWire) []byte {
	return rmJSON(t, struct {
		Contract  string `json:"contract"`
		Version   int    `json:"schema_version"`
		Kind      string `json:"kind"`
		Algorithm string `json:"algorithm"`
		Digest    string `json:"digest"`
	}{"open-trestle/revision-identity", 1, w.Kind, w.Algorithm, w.Digest})
}

func rmScopeBytes(t *testing.T, w rmScopeWire) []byte {
	return rmJSON(t, struct {
		Contract   string   `json:"contract"`
		Version    int      `json:"version"`
		Tenant     string   `json:"tenant"`
		Repository string   `json:"repository"`
		Actor      string   `json:"actor"`
		Visibility string   `json:"ref_visibility"`
		RefSet     string   `json:"ref_set_identity"`
		Prefixes   []string `json:"path_prefixes"`
	}{"open-trestle/memory-scope", 1, w.Tenant, w.Repository, w.Actor, w.Visibility, w.RefSet, w.Prefixes})
}

func rmNoteBytes(t *testing.T, scopeID string, r rmRecordWire) []byte {
	return rmJSON(t, []any{"open-trestle/operator-feedback-note", 1, scopeID, r.Path, r.Text, r.Observed, r.From, r.Until})
}

func rmRecordBytes(t *testing.T, scopeID string, r rmRecordWire) []byte {
	// Native empty arrays are null; only the new wire symbols array is [].
	return rmJSON(t, struct {
		Contract   string   `json:"contract"`
		Version    int      `json:"version"`
		Scope      string   `json:"scope"`
		Kind       string   `json:"kind"`
		Taint      string   `json:"taint"`
		Path       string   `json:"path"`
		Symbols    []string `json:"symbols"`
		TextDigest string   `json:"text_digest"`
		TextBytes  int      `json:"text_bytes"`
		Evidence   []string `json:"evidence"`
		Derived    []string `json:"derived_from"`
		Counter    []string `json:"counter_evidence"`
		Producer   string   `json:"producer"`
		Observed   int64    `json:"observed_at"`
		From       int64    `json:"valid_from"`
		Until      int64    `json:"valid_until"`
		Stale      int64    `json:"stale_after"`
		Freshness  string   `json:"freshness"`
		Confidence uint16   `json:"confidence"`
	}{"open-trestle/memory-record", 1, scopeID, r.Kind, r.Taint, r.Path, nil,
		rmHash([]byte(r.Text)), len(r.Text), r.Evidence, nil, nil, r.Producer,
		r.Observed, r.From, r.Until, 0, "", 0})
}

func rmInputBytes(t *testing.T, w rmEnvelopeWire) []byte {
	return rmJSON(t, []any{"open-trestle/protected-retained-input", 1, "local-only", 65536, 16, 16, 4096, 1024, 8192, 32768, 604800000, w})
}

func rmScope(t *testing.T, w rmScopeWire) memory.Scope {
	t.Helper()
	visibility, err := memory.ParseRefVisibility(w.Visibility)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := memory.NewScope(w.Tenant, w.Repository, w.Actor, visibility, w.RefSet, w.Prefixes)
	if err != nil || scope.Validate() != nil {
		t.Fatal("invalid native scope fixture")
	}
	if scope.Identity() != rmHash(rmScopeBytes(t, w)) || scope.Identity() != w.Identity ||
		scope.TenantID() != w.Tenant || scope.RepositoryID() != w.Repository || scope.ActorID() != w.Actor ||
		scope.RefVisibility().String() != w.Visibility || scope.RefSetIdentity() != w.RefSet ||
		!reflect.DeepEqual(scope.PathPrefixes(), w.Prefixes) {
		t.Fatal("native scope recipe drift")
	}
	return scope
}

func rmNativeRecord(t *testing.T, scope memory.Scope, r rmRecordWire) memory.Record {
	t.Helper()
	kind, err := memory.ParseRecordKind(r.Kind)
	if err != nil {
		t.Fatal(err)
	}
	taint, err := memory.ParseTaintClass(r.Taint)
	if err != nil {
		t.Fatal(err)
	}
	record, err := memory.NewRecord(scope, memory.RecordInput{
		Kind: kind, Taint: taint, Path: r.Path, Text: r.Text, EvidenceIDs: r.Evidence,
		ProducerIdentity: r.Producer, ObservedAt: time.UnixMilli(r.Observed).UTC(),
		ValidFrom: time.UnixMilli(r.From).UTC(), ValidUntil: time.UnixMilli(r.Until).UTC(),
	})
	if err != nil || record.Validate() != nil || record.Identity() != r.Identity {
		t.Fatal("native record recipe drift")
	}
	return record
}

func rmReseal(t *testing.T, w *rmEnvelopeWire, native bool) {
	t.Helper()
	w.Head.Identity = rmHash(rmHeadBytes(t, w.Head))
	w.Scope.RefSet = w.Head.Identity
	w.Scope.Identity = rmHash(rmScopeBytes(t, w.Scope))
	for i := range w.Records {
		r := &w.Records[i]
		r.Evidence = []string{"operator-note:" + rmHash(rmNoteBytes(t, w.Scope.Identity, *r))}
		r.Identity = rmHash(rmRecordBytes(t, w.Scope.Identity, *r))
	}
	sort.Strings(w.Paths)
	sort.Slice(w.Records, func(i, j int) bool { return w.Records[i].Identity < w.Records[j].Identity })
	if native {
		head, err := evidence.NewRevisionIdentity(evidence.RevisionKind(w.Head.Kind), evidence.RevisionAlgorithm(w.Head.Algorithm), w.Head.Digest)
		if err != nil || head.Identity() != w.Head.Identity || string(head.Kind()) != w.Head.Kind || string(head.Algorithm()) != w.Head.Algorithm || head.Digest() != w.Head.Digest {
			t.Fatal("native head recipe drift")
		}
		scope := rmScope(t, w.Scope)
		for _, record := range w.Records {
			rmNativeRecord(t, scope, record)
		}
	}
}

// The existing Clock seam controls time. This observer reads only native journal
// events. It neither substitutes a store/handler nor appends a success event.
type rmClock struct {
	mu      sync.Mutex
	at      time.Time
	journal controlplane.RunJournal
	scope   audit.ReviewScope
	expire  time.Time
	jumped  bool
}

func (c *rmClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.journal != nil && !c.jumped {
		events, err := c.journal.Read(context.Background(), c.scope, 0, 1000)
		if err == nil {
			for _, e := range events {
				if e.Kind() == controlplane.RunEventTaskSucceeded && e.TaskKey() == "context" {
					c.at, c.jumped = c.expire, true
					break
				}
			}
		}
	}
	return c.at
}
func (c *rmClock) set(at time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.at = at }
func (c *rmClock) arm(s *Session, scope audit.ReviewScope, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.journal, c.scope, c.expire = s.journal, scope, at
}
func rmOptions(t *testing.T, f *rmModelFixture, c *rmClock) SessionOptions {
	t.Helper()
	inventory, policy, err := runtimeconfig.LoadProtectedConfiguration(context.Background(), f.inventoryPath, f.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"private", "team"}, "sample")
	if err != nil {
		t.Fatal(err)
	}
	objects, err := os.OpenRoot(f.objects)
	if err != nil {
		t.Fatal(err)
	}
	// Cleanup may repeat Close after Session took ownership, but never runs while
	// a Run is active: all barrier tests explicitly drain before returning.
	t.Cleanup(func() { _ = objects.Close() })
	credentials, err := runtimecatalog.NewEnvironmentOpenAICredentialResolver(func(name string) string {
		if name == "OPEN_TRESTLE_PROVIDER_LOCAL_TEST_A" || name == "OPEN_TRESTLE_PROVIDER_LOCAL_TEST_B" {
			return rmModelKey
		}
		t.Error("unapproved credential reference")
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	return SessionOptions{TenantID: "tenant-local", RepositoryID: "repository-local", Repository: repository,
		ObjectsRoot: objects, Inventory: inventory, Policy: policy, Egress: EgressLocalOnly, Credentials: credentials,
		Clock: c, Timeout: 5 * time.Second, ArtifactCapacity: 128}
}
func rmRevisions(t *testing.T, f *rmModelFixture) (evidence.RevisionIdentity, evidence.RevisionIdentity) {
	t.Helper()
	base, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, f.base)
	if err != nil {
		t.Fatal(err)
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, f.head)
	if err != nil {
		t.Fatal(err)
	}
	return base, head
}
func rmEnvelopeFor(t *testing.T, o SessionOptions, head evidence.RevisionIdentity, paths []string, until time.Time) rmEnvelopeWire {
	t.Helper()
	observed := o.Clock.Now().UnixMilli()
	w := rmEnvelopeWire{Contract: "open-trestle/retained-memory-input", Version: 1, Attestation: "operator_attested_advisory_feedback",
		Scope:      rmScopeWire{Tenant: o.TenantID, Repository: o.RepositoryID, Actor: "local-reviewer", Visibility: "exact", Prefixes: []string{"."}},
		Repository: o.Repository.Identity(), Head: rmHeadWire{Kind: string(head.Kind()), Algorithm: string(head.Algorithm()), Digest: head.Digest()},
		Policy: o.Policy.Identity(), Paths: append([]string(nil), paths...), Records: []rmRecordWire{}}
	for _, path := range paths {
		w.Records = append(w.Records, rmRecordWire{Kind: "human_feedback", Taint: "user_controlled", Path: path, Symbols: []string{}, Text: rmAdvice, Producer: rmProducer, Observed: observed, From: observed, Until: until.UnixMilli()})
	}
	rmReseal(t, &w, true)
	if w.Head.Identity != head.Identity() || w.Scope.RefSet == head.Digest() {
		t.Fatal("raw Git hash became scope authority")
	}
	return w
}
func rmWrite(t *testing.T, w rmEnvelopeWire) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "operator-feedback.json")
	if err := os.WriteFile(path, rmJSON(t, w), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func rmLoad(t *testing.T, path string, w rmEnvelopeWire, o SessionOptions) runtimeconfig.RetainedMemoryInput {
	t.Helper()
	v, err := runtimeconfig.LoadProtectedRetainedMemoryInput(context.Background(), path, rmScope(t, w.Scope), o.Repository, o.Policy, o.Clock.Now())
	if err != nil || v.Identity() != rmHash(rmInputBytes(t, w)) || len(v.Records()) != len(w.Records) {
		t.Fatal("protected input admission or independent identity mismatch")
	}
	return v
}
func rmSession(t *testing.T, o SessionOptions) *Session {
	t.Helper()
	s, err := NewSession(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rmClose(t, s) })
	return s
}
func rmClose(t *testing.T, s *Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Error(err)
	}
}
func rmPrepare(t *testing.T, s *Session, f *rmModelFixture, id string) runtimecatalog.PreparedReviewRun {
	t.Helper()
	scope, err := audit.NewReviewScope(s.options.TenantID, s.options.RepositoryID, id)
	if err != nil {
		t.Fatal(err)
	}
	base, head := rmRevisions(t, f)
	p, err := s.Prepare(context.Background(), scope, rmHash([]byte(id)), base, head)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func rmNoCalls(t *testing.T, f *rmModelFixture) {
	t.Helper()
	g, _ := f.generation.snapshot()
	v, _ := f.verification.snapshot()
	if g != 0 || v != 0 {
		t.Fatal("refusal dispatched an external model")
	}
}

type rmForbiddenCredentials struct{ calls int }

func (r *rmForbiddenCredentials) ResolveOpenAICredentials(string) (openai.APIKeyProvider, error) {
	r.calls++
	return nil, errors.New("forbidden test credential resolution")
}
