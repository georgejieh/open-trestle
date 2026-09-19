package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const investigationNotes = "deployment notes\r\nConsume is enabled for zero-valued requests.\r\nnot selected by symbol analysis\n"
const investigationLine = "Consume is enabled for zero-valued requests.\r\n"

type investigationFile struct {
	Ref    string `json:"ref"`
	Path   string `json:"path"`
	Digest string `json:"digest"`
}
type investigationToolResult struct {
	ArtifactIdentity string              `json:"artifact_identity"`
	Identity         string              `json:"identity"`
	Operation        string              `json:"operation_identity"`
	Tool             string              `json:"tool"`
	Snapshot         string              `json:"snapshot_identity"`
	Files            []investigationFile `json:"files"`
	Sources          []struct {
		localModelSource
		Binding string `json:"binding_identity"`
		Digest  string `json:"repository_file_digest"`
	} `json:"sources"`
}
type investigationPacket struct {
	localModelPacket
	Investigation struct {
		Session         string                    `json:"session_identity"`
		Policy          string                    `json:"policy_identity"`
		Snapshot        string                    `json:"snapshot_identity"`
		SnapshotRef     string                    `json:"snapshot_ref"`
		Turn            uint32                    `json:"turn"`
		PreviousRequest string                    `json:"previous_request_identity"`
		PreviousOutcome string                    `json:"previous_outcome_identity"`
		PreviousResults []string                  `json:"previous_tool_result_identities"`
		MemoryState     string                    `json:"memory_state"`
		Results         []investigationToolResult `json:"tool_results"`
	} `json:"investigation"`
}
type investigationCapture struct {
	packet  investigationPacket
	request string
}
type investigationEndpoint struct {
	mu       sync.Mutex
	captures []investigationCapture
	mode     string
	cancel   context.CancelFunc
}

func (e *investigationEndpoint) snapshot() []investigationCapture {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]investigationCapture(nil), e.captures...)
}
func (e *investigationEndpoint) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, (8<<20)+1))
	var wire struct {
		Model string `json:"model"`
		Input []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"input"`
	}
	if err != nil || len(body) > 8<<20 || json.Unmarshal(body, &wire) != nil || len(wire.Input) != 1 || len(wire.Input[0].Content) != 1 || r.Method != "POST" || r.URL.Path != "/v1/responses" {
		t.Error("invalid bounded Responses request")
		http.Error(w, "invalid", 400)
		return
	}
	payload := []byte(wire.Input[0].Content[0].Text)
	var p investigationPacket
	request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", payload)
	if err != nil || json.Unmarshal(payload, &p) != nil {
		t.Error("invalid provider-neutral payload")
		http.Error(w, "invalid", 400)
		return
	}
	e.mu.Lock()
	e.captures = append(e.captures, investigationCapture{p, request.Identity()})
	e.mu.Unlock()
	var output any
	if p.Task == "candidate_verification" {
		if wire.Model != "model-b" || p.Version != 3 || len(p.Candidates) != 1 || p.GenerationContext == "" {
			t.Error("independent verifier lost candidate lineage")
		}
		ids := []string{}
		for _, s := range p.Sources {
			if s.Path == "a.go" || s.Path == "notes.txt" {
				ids = append(ids, s.ID)
			}
		}
		if len(ids) != 2 || len(p.Candidates) != 1 {
			http.Error(w, "missing evidence", 400)
			return
		}
		output = map[string]any{"schema_version": 1, "verdicts": []any{map[string]any{"candidate_id": p.Candidates[0].ID, "outcome": "verified", "severity": "high", "rationale": "The division guard is absent and the cited deployment text enables zero requests.", "evidence_ids": ids}}}
	} else {
		state := p.Investigation
		if wire.Model != "model-a" || p.Version != 4 || state.MemoryState != "empty_not_ingested" || state.Session == "" || state.Policy == "" || state.Snapshot == "" {
			t.Error("investigation did not receive explicit v4 authority and empty memory label")
			http.Error(w, "invalid authority", 400)
			return
		}
		if e.mode == "cumulative cost" || e.mode == "verifier cost" {
			usage := uint64(49000)
			if e.mode == "verifier cost" {
				usage = 24000
			}
			remaining := uint64(100000) - usage*uint64(state.Turn-1)
			if uint64(len(payload))+256+4096 > remaining {
				t.Error("dispatched turn cannot fit actual remaining priced capacity")
			}
		}
		call := map[string]any{"call_id": "list-1", "tool": "snapshot.list", "snapshot_ref": state.SnapshotRef}
		switch state.Turn {
		case 1:
			for _, s := range p.Sources {
				if s.Path == "notes.txt" {
					t.Error("target was preselected before model investigation")
				}
			}
			if state.PreviousRequest != "" || state.PreviousOutcome != "" || len(state.Results) != 0 {
				t.Error("initial turn contains invented lineage")
			}
		case 2:
			var ref string
			for _, result := range state.Results {
				for _, f := range result.Files {
					if f.Path == "notes.txt" {
						ref = f.Ref
					}
				}
			}
			if ref == "" {
				t.Error("listing omitted actual unselected snapshot reference")
				http.Error(w, "missing reference", 400)
				return
			}
			call = map[string]any{"call_id": "read-1", "tool": "snapshot.read", "snapshot_ref": state.SnapshotRef, "file_ref": ref, "start_line": 2, "end_line": 2}
		case 3:
			var ref string
			found := false
			for _, result := range state.Results {
				for _, f := range result.Files {
					if f.Path == "notes.txt" {
						ref = f.Ref
					}
				}
				for _, s := range result.Sources {
					if s.Path == "notes.txt" && s.Content == investigationLine && s.Start == 2 && s.End == 2 && s.Binding != "" && s.Digest == localModelDigest([]byte(investigationNotes)) {
						found = true
					}
				}
			}
			if !found || ref == "" {
				t.Error("read did not bind exact physical CRLF bytes")
				http.Error(w, "missing read", 400)
				return
			}
			call = map[string]any{"call_id": "search-1", "tool": "snapshot.search", "snapshot_ref": state.SnapshotRef, "file_refs": []string{ref}, "literal": "zero-valued"}
		case 4:
			found := false
			for _, result := range state.Results {
				if result.Tool == "snapshot.search" {
					for _, s := range result.Sources {
						if s.Path == "notes.txt" && s.Content == investigationLine && s.Start == 2 && s.End == 2 && s.Binding != "" {
							found = true
						}
					}
				}
			}
			var changed localModelSource
			ids := []string{}
			for _, s := range p.Sources {
				if s.Path == "a.go" {
					changed = s
					ids = append(ids, s.ID)
				}
				if s.Path == "notes.txt" {
					if s.Stage != "repository_context" || s.Content != investigationLine {
						t.Error("tool evidence grade or bytes changed")
					}
					ids = append(ids, s.ID)
				}
			}
			if !found || changed.ID == "" || len(ids) != 2 {
				t.Error("search never reached final admitted candidate context")
				http.Error(w, "missing search", 400)
				return
			}
			output = map[string]any{"schema_version": 1, "candidates": []any{map[string]any{"title": "Enabled zero requests panic", "claim": "Deployment enables zero requests while Changed divides without a guard.", "severity_hint": "high", "source_range": map[string]any{"source_id": changed.ID, "start_line": 2, "end_line": 2}, "evidence_ids": ids}}}
		default:
			t.Error("unbounded or repeated model turn")
			http.Error(w, "unexpected turn", 400)
			return
		}
		if output == nil {
			if state.Turn == 2 {
				switch e.mode {
				case "unknown ref":
					call["file_ref"] = strings.Repeat("f", 64)
				case "traversal":
					call["file_ref"] = "../objects/secret"
				case "absolute":
					call["file_ref"] = "/etc/passwd"
				case "wrong snapshot":
					call["snapshot_ref"] = strings.Repeat("e", 64)
				case "unsupported":
					call["tool"] = "shell"
				case "oversized range":
					call["end_line"] = 1000000
				case "extra field":
					call["path"] = "notes.txt"
				case "duplicate operation":
					call = map[string]any{"call_id": "list-1", "tool": "snapshot.list", "snapshot_ref": state.SnapshotRef}
				case "cancel":
					e.cancel()
				}
			}
			output = map[string]any{"schema_version": 1, "tool_calls": []any{call}}
		}
	}
	text, err := json.Marshal(output)
	if err != nil {
		t.Error(err)
		return
	}
	if e.mode == "malformed" && p.Investigation.Turn == 2 {
		text = []byte(`{"schema_version":1,"tool_calls":[`)
	}
	response := map[string]any{"id": "bounded-response", "object": "response", "status": "completed", "model": wire.Model,
		"output": []any{map[string]any{"id": "bounded-message", "type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": string(text)}}}},
		"usage":  map[string]any{"input_tokens": 100, "output_tokens": 100, "total_tokens": 200}}
	if e.mode == "cumulative cost" && p.Investigation.Turn > 0 {
		response["usage"] = map[string]any{"input_tokens": 48000, "output_tokens": 1000, "total_tokens": 49000}
	}
	if e.mode == "verifier cost" && p.Investigation.Turn > 0 {
		response["usage"] = map[string]any{"input_tokens": 23000, "output_tokens": 1000, "total_tokens": 24000}
	}
	if e.mode == "unknown usage" && p.Investigation.Turn == 2 {
		delete(response, "usage")
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil && e.mode != "cancel" {
		t.Error(err)
	}
}

func newInvestigationFixture(t *testing.T, mode string, cancel context.CancelFunc) (*localModelFixture, *investigationEndpoint, map[string]any, string) {
	t.Helper()
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	base := map[string][]byte{"a.go": []byte("package p\nfunc Changed(x int) int { if x == 0 { return 0 }; return 10 / x }\n"), "notes.txt": []byte(investigationNotes)}
	head := map[string][]byte{"a.go": []byte("package p\nfunc Changed(x int) int { return 10 / x }\n"), "notes.txt": base["notes.txt"]}
	f.objects, f.base, f.head = writeLocalGitChangeFixture(t, evidence.RevisionAlgorithmSHA1, base, head)
	e := &investigationEndpoint{mode: mode, cancel: cancel}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { e.serve(t, w, r) }))
	t.Cleanup(server.Close)
	encoded, err := os.ReadFile(f.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]any
	if json.Unmarshal(encoded, &policy) != nil {
		t.Fatal("invalid runtime fixture policy")
	}
	for _, connection := range policy["connections"].([]any) {
		connection.(map[string]any)["endpoint"] = server.URL + "/v1"
	}
	if mode == "cumulative cost" || mode == "verifier cost" {
		inventoryBytes, err := os.ReadFile(f.inventoryPath)
		if err != nil {
			t.Fatal(err)
		}
		var inventoryWire map[string]any
		if json.Unmarshal(inventoryBytes, &inventoryWire) != nil {
			t.Fatal("invalid route fixture")
		}
		for _, entry := range inventoryWire["routes"].([]any) {
			route := entry.(map[string]any)
			route["input_micro_usd_per_million_tokens"] = 1000000
			route["output_micro_usd_per_million_tokens"] = 1000000
		}
		inventoryBytes = localModelJSON(t, inventoryWire)
		inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryBytes))
		if err != nil {
			t.Fatal(err)
		}
		policy["inventory_identity"] = inventory.Identity()
		policy["max_cost_micro_usd"] = 100000
		for _, candidate := range inventory.Candidates() {
			record := candidate.ResolvedRecord().RouteRegistryRecord()
			if record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID() == "adapter-a" {
				policy["pinned_route_record_identity"] = record.Identity()
			} else {
				policy["preferred_route_record_identities"] = []string{record.Identity()}
			}
		}
		if err := os.WriteFile(f.inventoryPath, inventoryBytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.policyPath, localModelJSON(t, policy), 0o600); err != nil {
		t.Fatal(err)
	}
	limits := map[string]any{"contract": "open-trestle/investigation-policy", "schema_version": 1, "profile": "snapshot-read-v1", "max_model_turns": 5, "max_tool_calls": 3, "max_returned_bytes": 32768, "max_scanned_bytes": 65536, "max_files": 16, "max_lines_per_read": 20, "max_matches": 8, "max_result_bytes": 8192, "max_cost_micro_usd": 0, "timeout_milliseconds": 5000}
	if mode == "cumulative cost" || mode == "verifier cost" {
		limits["max_cost_micro_usd"] = 100000
	}
	path := filepath.Join(filepath.Dir(f.policyPath), "investigation.json")
	f.args = append([]string{"local-git", "model-review"}, localGitChangeArgs(f.objects, evidence.RevisionAlgorithmSHA1, f.base, f.head)...)
	f.args = append(f.args, "--tenant", "tenant-local", "--repository", "repository-local", "--route-inventory", f.inventoryPath, "--runtime-policy", f.policyPath, "--egress", "local-only", "--timeout", "5s", "--format", "json", "--investigation-policy", path)
	return f, e, limits, path
}
func writeInvestigationPolicy(t *testing.T, path string, policy map[string]any) {
	t.Helper()
	if err := os.WriteFile(path, localModelJSON(t, policy), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLocalGitInvestigationReadsUnselectedSnapshotAndVerifies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f, endpoint, policy, path := newInvestigationFixture(t, "", cancel)
	writeInvestigationPolicy(t, path, policy)
	f.args = replaceLocalGitChangeValue(f.args, "--timeout", "30s")
	var stdout, stderr bytes.Buffer
	code := runWithContext(ctx, f.args, &stdout, &stderr)
	if code == 2 {
		t.Fatal("explicit snapshot investigation opt-in is not implemented")
	}
	var receipt struct {
		localModelReceipt
		Investigation struct {
			Turns []struct {
				Request        string   `json:"request_identity"`
				Authorization  string   `json:"authorization_identity"`
				Outcome        string   `json:"outcome_identity"`
				Reconciliation string   `json:"reconciliation_identity"`
				Results        []string `json:"tool_result_identities"`
			} `json:"turns"`
			ToolCalls     uint32 `json:"tool_calls"`
			ReturnedBytes uint64 `json:"returned_bytes"`
		} `json:"investigation"`
	}
	if json.Unmarshal(stdout.Bytes(), &receipt) != nil || code != 4 || receipt.Status != "findings" || receipt.RunStatus != "succeeded" || receipt.Version != 2 || stderr.Len() != 0 {
		t.Fatal("investigation did not produce a bounded independent finding")
	}
	captures := endpoint.snapshot()
	if len(captures) != 5 || len(receipt.Investigation.Turns) != 5 || receipt.Investigation.ToolCalls != 3 || receipt.Investigation.ReturnedBytes == 0 || receipt.Investigation.ReturnedBytes > 32768 {
		t.Fatal("missing real turns, tools, or cumulative bounded receipt")
	}
	seen := map[string]bool{}
	seenAuthority := map[string]bool{}
	seenOutcome := map[string]bool{}
	seenReconciliation := map[string]bool{}
	claimed := map[string]bool{}
	completed := map[string]bool{}
	reconciled := map[string]bool{}
	for _, event := range receipt.Audit {
		if event.Kind == "route_attempt_claimed" {
			claimed[event.Subject] = true
		}
		if event.Kind == "route_dispatch_completed" {
			completed[event.Subject] = true
		}
		if event.Kind == "route_cost_reconciled" {
			reconciled[event.Subject] = true
		}
	}
	for i, c := range captures {
		turn := receipt.Investigation.Turns[i]
		localModelRequireDigest(t, turn.Request, turn.Authorization, turn.Outcome, turn.Reconciliation)
		if seen[c.request] || turn.Request != c.request {
			t.Fatal("successful turn reused request identity or receipt invented a request")
		}
		seen[c.request] = true
		if seenAuthority[turn.Authorization] || !claimed[turn.Authorization] {
			t.Fatal("new model turn lacks distinct actual route claim")
		}
		seenAuthority[turn.Authorization] = true
		if seenOutcome[turn.Outcome] || seenReconciliation[turn.Reconciliation] || !completed[turn.Outcome] || !reconciled[turn.Reconciliation] {
			t.Fatal("turn lost distinct ledger-bound outcome or cost reconciliation")
		}
		seenOutcome[turn.Outcome] = true
		seenReconciliation[turn.Reconciliation] = true
		if i > 0 && i < 4 {
			state := c.packet.Investigation
			prior := receipt.Investigation.Turns[i-1]
			if state.PreviousRequest != prior.Request || state.PreviousOutcome != prior.Outcome || strings.Join(state.PreviousResults, ",") != strings.Join(prior.Results, ",") || len(prior.Results) != 1 {
				t.Fatal("new request does not bind preceding admitted tool result and outcome")
			}
		}
	}
	if receipt.GenerationRequest != captures[3].request || receipt.VerificationRequest != captures[4].request || receipt.Context != captures[4].packet.GenerationContext || receipt.CandidateBatch != captures[4].packet.CandidateBatch || len(receipt.CandidateIDs) != 1 || receipt.CandidateIDs[0] != captures[4].packet.Candidates[0].ID {
		t.Fatal("final output is disconnected from actual generation and independent verification")
	}
	if receipt.Diagnostics.Coverage.VerifiedCount != 1 || len(receipt.Diagnostics.Findings) != 1 || receipt.Independence != "distinct_provider" || receipt.ComprehensiveClearance {
		t.Fatal("tool evidence bypassed independent finding admission")
	}
	for _, task := range receipt.Tasks {
		if task.Key == "publication" || task.MaxAttempts != 1 && (task.Key == "context" || task.Key == "candidates" || task.Key == "verification") {
			t.Fatal("investigation gained publication or task replay authority")
		}
	}
	for _, event := range receipt.Audit {
		if strings.HasPrefix(event.Kind, "publication_") {
			t.Fatal("read-only investigation gained publication authority")
		}
	}
	if strings.Contains(stdout.String()+stderr.String(), investigationLine) || stdout.Len() > 256<<10 {
		t.Fatal("terminal result leaked tool bytes or exceeded output limit")
	}
}

func TestLocalGitInvestigationRefusesUnsafeContinuation(t *testing.T) {
	for _, mode := range []string{"unknown ref", "traversal", "absolute", "wrong snapshot", "unsupported", "oversized range", "extra field", "duplicate operation", "malformed", "unknown usage", "cancel", "turn limit", "byte limit", "call limit", "cumulative cost", "verifier cost"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			f, endpoint, policy, path := newInvestigationFixture(t, mode, cancel)
			switch mode {
			case "turn limit":
				policy["max_model_turns"] = 2
			case "byte limit":
				policy["max_returned_bytes"] = 1
			case "call limit":
				policy["max_tool_calls"] = 1
			}
			writeInvestigationPolicy(t, path, policy)
			var stdout, stderr bytes.Buffer
			code := runWithContext(ctx, f.args, &stdout, &stderr)
			if code == 2 {
				t.Fatal("opt-in parser refusal is not a continuation safety proof")
			}
			var receipt localModelReceipt
			if json.Unmarshal(stdout.Bytes(), &receipt) != nil || receipt.RunStatus == "succeeded" || receipt.Readiness != "" || receipt.Diagnostics.Coverage.VerifiedCount != 0 || code == 0 {
				t.Fatal("invalid continuation produced successful downstream authority")
			}
			captures := endpoint.snapshot()
			want := 2
			if mode == "byte limit" {
				want = 1
			}
			if mode == "verifier cost" {
				want = 4
			}
			if len(captures) != want {
				t.Fatalf("model calls=%d want=%d; refusal must follow real proposal and suppress next dispatch", len(captures), want)
			}
			for _, c := range captures {
				if c.packet.Task == "candidate_verification" {
					t.Fatal("refused investigation reached verifier")
				}
			}
		})
	}
}
