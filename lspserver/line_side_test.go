package lspserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
)

func TestServerShowsBaseLinesAsAFileLevelDiagnostic(t *testing.T) {
	deterministic := lspDeterministicSet(t)
	// A head finding and a base-side finding at the same path and numbers.
	head := lspDiagnosticSet(t).Findings()[0]
	base, err := diagnostics.NewFindingOnSide(strings.Repeat("a", 64), strings.Repeat("d", 64), "Removed guard", "The zero check was removed.", diagnostics.SeverityError, head.Path(), diagnostics.LineSideBase, head.StartLine(), head.EndLine(), []string{"evidence-1"})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := diagnostics.NewSetWithDeterministicChecks(deterministic.Scope(), strings.Repeat("9", 64), deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 2, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), []diagnostics.Finding{head, base})
	if err != nil || verified.SchemaVersion() != 8 {
		t.Fatalf("verified=%v", err)
	}
	final, err := diagnostics.NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), diagnostics.FinalOutcomeCompleted, deterministic, verified)
	if err != nil {
		t.Fatal(err)
	}
	for name, set := range map[string]diagnostics.Set{"version 8": verified, "final version 7": final} {
		server, err := New(&diagnosticReaderStub{set: set})
		if err != nil {
			t.Fatal(err)
		}
		var input bytes.Buffer
		input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"rootUri": "file:///workspace", "initializationOptions": map[string]any{"tenant_id": "tenant-a", "repository_id": "repo-a", "review_run_id": "run-a"}}}))
		input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "method": "initialized", "params": map[string]any{}}))
		input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "textDocument/diagnostic", "params": map[string]any{"textDocument": map[string]any{"uri": "file:///workspace/" + head.Path()}}}))
		input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": nil}))
		input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "method": "exit"}))
		var output bytes.Buffer
		if err := server.Serve(context.Background(), &input, &output); err != nil {
			t.Fatal(err)
		}
		bodies := decodeLSPFrames(t, output.Bytes())
		if len(bodies) != 3 {
			t.Fatalf("%s: responses=%d", name, len(bodies))
		}
		var response struct {
			Result struct {
				Items []struct {
					Range struct {
						Start struct {
							Line      uint32 `json:"line"`
							Character uint32 `json:"character"`
						} `json:"start"`
						End struct {
							Line      uint32 `json:"line"`
							Character uint32 `json:"character"`
						} `json:"end"`
					} `json:"range"`
					Message string         `json:"message"`
					Data    map[string]any `json:"data"`
				} `json:"items"`
			} `json:"result"`
		}
		if err := json.Unmarshal(bodies[1], &response); err != nil {
			t.Fatal(err)
		}
		items := response.Result.Items
		if len(items) != 2 {
			t.Fatalf("%s: items=%s", name, bodies[1])
		}
		placed, fileLevel := items[0], items[1]
		if placed.Range.Start.Line != head.StartLine()-1 || placed.Range.End.Line != head.EndLine() || placed.Data["side"] != nil {
			t.Fatalf("%s: head finding moved: %s", name, bodies[1])
		}
		// The base-side finding is file-level and names its base lines; it is
		// never drawn at head lines with the same numbers.
		if fileLevel.Range.Start.Line != 0 || fileLevel.Range.End.Line != 0 || fileLevel.Range.End.Character != 0 ||
			!strings.HasPrefix(fileLevel.Message, "Base lines 3-4 (removed code): Removed guard") ||
			!strings.HasSuffix(fileLevel.Message, "[untrusted review output; verify before editing]") ||
			fileLevel.Data["side"] != "base" || fileLevel.Data["base_start_line"] != float64(3) || fileLevel.Data["base_end_line"] != float64(4) {
			t.Fatalf("%s: base-side finding was placed at head lines: %s", name, bodies[1])
		}
	}
}
