package lspserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
	"strings"
	"testing"
)

type diagnosticReaderStub struct {
	set   diagnostics.Set
	calls int
}

func (r *diagnosticReaderStub) GetDiagnosticSet(context.Context, audit.ReviewScope) (diagnostics.Set, error) {
	r.calls++
	return r.set, nil
}
func lspDiagnosticSet(t *testing.T) diagnostics.Set {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	finding, _ := diagnostics.NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Nil access", "The value may be nil.", diagnostics.SeverityError, "internal/example.go", 3, 4, []string{"evidence-1"})
	set, _ := diagnostics.NewSetWithSourceCoverage(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64), 1, 0, 0, 2, 1, 1, []diagnostics.Finding{finding})
	return set
}
func lspFrame(value any) []byte {
	body, _ := json.Marshal(value)
	return []byte(fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body))
}
func TestServerInitializesAndReturnsVerifiedPullDiagnostics(t *testing.T) {
	reader := &diagnosticReaderStub{set: lspDiagnosticSet(t)}
	server, err := New(reader)
	if err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"rootUri": "file:///workspace", "initializationOptions": map[string]any{"tenant_id": "tenant-a", "repository_id": "repo-a", "review_run_id": "run-a"}}}))
	input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "method": "initialized", "params": map[string]any{}}))
	input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "textDocument/diagnostic", "params": map[string]any{"textDocument": map[string]any{"uri": "file:///workspace/internal/example.go"}}}))
	input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": nil}))
	input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "method": "exit"}))
	var output bytes.Buffer
	if err := server.Serve(context.Background(), &input, &output); err != nil {
		t.Fatal(err)
	}
	bodies := decodeLSPFrames(t, output.Bytes())
	if len(bodies) != 3 || reader.calls != 1 {
		t.Fatalf("responses=%d calls=%d output=%q", len(bodies), reader.calls, output.String())
	}
	type position struct {
		Line      uint32 `json:"line"`
		Character uint32 `json:"character"`
	}
	var diagnostic struct {
		Result struct {
			Kind     string `json:"kind"`
			ResultID string `json:"resultId"`
			Items    []struct {
				Range struct {
					Start position `json:"start"`
					End   position `json:"end"`
				} `json:"range"`
				Severity int    `json:"severity"`
				Code     string `json:"code"`
				Source   string `json:"source"`
				Message  string `json:"message"`
			} `json:"items"`
		} `json:"result"`
	}
	if err := json.Unmarshal(bodies[1], &diagnostic); err != nil || diagnostic.Result.Kind != "full" || diagnostic.Result.ResultID != reader.set.Identity() || len(diagnostic.Result.Items) != 1 {
		t.Fatalf("diagnostic=(%#v,%v)", diagnostic, err)
	}
	item := diagnostic.Result.Items[0]
	if item.Range.Start.Line != 2 || item.Range.End.Line != 4 || item.Severity != 1 || item.Source != "open-trestle" || !strings.Contains(item.Message, "untrusted review output") {
		t.Fatalf("item=%#v", item)
	}
}
func decodeLSPFrames(t *testing.T, encoded []byte) [][]byte {
	t.Helper()
	var bodies [][]byte
	for len(encoded) > 0 {
		separator := bytes.Index(encoded, []byte("\r\n\r\n"))
		if separator < 0 {
			t.Fatalf("invalid frame %q", encoded)
		}
		var length int
		if _, err := fmt.Sscanf(string(encoded[:separator]), "Content-Length: %d", &length); err != nil {
			t.Fatal(err)
		}
		encoded = encoded[separator+4:]
		if length < 0 || length > len(encoded) {
			t.Fatal("invalid length")
		}
		bodies = append(bodies, append([]byte(nil), encoded[:length]...))
		encoded = encoded[length:]
	}
	return bodies
}

func TestServerRejectsDocumentOutsideInitializedRootBeforeReading(t *testing.T) {
	reader := &diagnosticReaderStub{set: lspDiagnosticSet(t)}
	server, _ := New(reader)
	var input bytes.Buffer
	input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"rootUri": "file:///workspace/", "initializationOptions": map[string]any{"tenant_id": "tenant-a", "repository_id": "repo-a", "review_run_id": "run-a"}}}))
	input.Write(lspFrame(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "textDocument/diagnostic", "params": map[string]any{"textDocument": map[string]any{"uri": "file:///other/file.go"}}}))
	var output bytes.Buffer
	if err := server.Serve(context.Background(), &input, &output); err != nil {
		t.Fatal(err)
	}
	bodies := decodeLSPFrames(t, output.Bytes())
	if len(bodies) != 2 || reader.calls != 0 || !bytes.Contains(bodies[1], []byte(`"error"`)) {
		t.Fatalf("responses=%d calls=%d output=%q", len(bodies), reader.calls, output.String())
	}
}
func TestServerRejectsOversizedHeaderWithoutUnboundedRead(t *testing.T) {
	server, _ := New(&diagnosticReaderStub{set: lspDiagnosticSet(t)})
	input := bytes.NewBufferString("X-Long: " + strings.Repeat("x", maxLSPHeaderBytes) + "\r\n\r\n")
	var output bytes.Buffer
	if err := server.Serve(context.Background(), input, &output); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("error=%v", err)
	}
}
