package lspserver

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
)

func TestServerFinalV7PullPreservesVerifiedReviewSnapshot(t *testing.T) {
	deterministic := lspDeterministicSet(t)
	finding := lspDiagnosticSet(t).Findings()[0]
	reviewSnapshot := strings.Repeat("9", 64)
	verified, err := diagnostics.NewSetWithDeterministicChecks(deterministic.Scope(), reviewSnapshot, deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), []diagnostics.Finding{finding})
	if err != nil {
		t.Fatal(err)
	}
	final, err := diagnostics.NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), diagnostics.FinalOutcomeCompleted, deterministic, verified)
	if err != nil || final.Validate() != nil || final.SnapshotIdentity() == final.ReviewSnapshotIdentity() || final.ReviewSnapshotIdentity() != reviewSnapshot {
		t.Fatalf("distinct physical/review snapshot fixture: %v", err)
	}
	encoded, err := diagnostics.EncodeSet(final)
	if err != nil {
		t.Fatal(err)
	}
	final, err = diagnostics.ParseSet(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reader := &diagnosticReaderStub{set: final}
	server, err := New(reader)
	if err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"rootUri": "file:///workspace", "initializationOptions": map[string]any{"tenant_id": "tenant-a", "repository_id": "repo-a", "review_run_id": "run-a"}}}))
	input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "method": "initialized", "params": map[string]any{}}))
	input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "textDocument/diagnostic", "params": map[string]any{"textDocument": map[string]any{"uri": "file:///workspace/internal/example.go"}}}))
	input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "textDocument/diagnostic", "params": map[string]any{"textDocument": map[string]any{"uri": "file:///workspace/internal/example.go"}, "previousResultId": final.Identity()}}))
	input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "id": 4, "method": "shutdown", "params": nil}))
	input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "method": "exit"}))
	var output bytes.Buffer
	if err := server.Serve(context.Background(), &input, &output); err != nil {
		t.Fatal(err)
	}
	bodies := decodeLSPFrames(t, output.Bytes())
	if len(bodies) != 4 || reader.calls != 2 {
		t.Fatalf("responses=%d calls=%d", len(bodies), reader.calls)
	}
	var response struct {
		Result struct {
			Kind     string `json:"kind"`
			ResultID string `json:"resultId"`
			Items    []struct {
				Range struct {
					Start struct {
						Line uint32 `json:"line"`
					} `json:"start"`
					End struct {
						Line uint32 `json:"line"`
					} `json:"end"`
				} `json:"range"`
				Data struct {
					DiagnosticIdentity    string   `json:"diagnostic_identity"`
					SourceIdentity        string   `json:"source_identity"`
					EvidenceIDs           []string `json:"evidence_ids"`
					DiagnosticSetIdentity string   `json:"diagnostic_set_identity"`
					SnapshotIdentity      string   `json:"snapshot_identity"`
					HeadRevision          string   `json:"head_revision"`
				} `json:"data"`
			} `json:"items"`
		} `json:"result"`
	}
	if err := json.Unmarshal(bodies[1], &response); err != nil || response.Result.Kind != "full" || response.Result.ResultID != final.Identity() || len(response.Result.Items) != 1 {
		t.Fatalf("full V7 pull: %s error=%v", bodies[1], err)
	}
	item := response.Result.Items[0]
	if item.Data.DiagnosticIdentity != finding.Identity() || item.Data.SourceIdentity != finding.SourceIdentity() || !reflect.DeepEqual(item.Data.EvidenceIDs, finding.EvidenceIDs()) || item.Data.DiagnosticSetIdentity != final.Identity() || item.Data.HeadRevision != final.HeadRevision() || item.Range.Start.Line != finding.StartLine()-1 || item.Range.End.Line != finding.EndLine() {
		t.Fatalf("finding evidence changed: %+v", item)
	}
	if item.Data.SnapshotIdentity != verified.SnapshotIdentity() {
		t.Errorf("verified finding snapshot_identity=%s, want selected review snapshot=%s; physical head snapshot=%s", item.Data.SnapshotIdentity, verified.SnapshotIdentity(), final.SnapshotIdentity())
	}
	var unchanged struct {
		Result struct {
			Kind     string `json:"kind"`
			ResultID string `json:"resultId"`
		} `json:"result"`
	}
	if err := json.Unmarshal(bodies[2], &unchanged); err != nil || unchanged.Result.Kind != "unchanged" || unchanged.Result.ResultID != final.Identity() {
		t.Fatalf("unchanged result identity: %s error=%v", bodies[2], err)
	}
}
