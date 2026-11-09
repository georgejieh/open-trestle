package lspserver

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
)

func TestServerNeverPlacesBaseLinesOnAHeadDocument(t *testing.T) {
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
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(bodies[1], &response); err != nil {
			t.Fatal(err)
		}
		if response.Error == nil || response.Error.Code != -32603 || response.Result != nil {
			t.Fatalf("%s: base-side finding was placed on the head document: %s", name, bodies[1])
		}
	}
}
