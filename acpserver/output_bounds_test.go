package acpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
)

func TestServerOmitsDiagnosticsThatExceedEscapedFrameBudget(t *testing.T) {
	scope, receipt, _ := acpFixture(t)
	findings := make([]diagnostics.Finding, 37)
	for i := range findings {
		var err error
		findings[i], err = diagnostics.NewFinding(fmt.Sprintf("%064x", i+1), fmt.Sprintf("%064x", i+101), "verified issue", strings.Repeat("<", 4096), diagnostics.SeverityWarning, "a.go", 1, 1, []string{strings.Repeat("c", 64)})
		if err != nil {
			t.Fatal(err)
		}
	}
	set, err := diagnostics.NewSet(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), findings)
	if err != nil {
		t.Fatal(err)
	}
	encodedSet, err := diagnostics.EncodeSet(set)
	if err != nil || len(encodedSet) >= maxACPMessageBytes-4096 {
		t.Fatalf("fixture outside original budget: bytes=%d err=%v", len(encodedSet), err)
	}
	escaped, err := json.Marshal(agentMessage(strings.Repeat("a", 32), string(encodedSet)))
	if err != nil || len(escaped) <= maxACPMessageBytes {
		t.Fatalf("fixture does not exceed escaped budget: bytes=%d err=%v", len(escaped), err)
	}
	service := &serviceStub{receipt: receipt, set: set}
	server, err := New(service, scope)
	if err != nil {
		t.Fatal(err)
	}
	server.initialized = true
	session := strings.Repeat("a", 32)
	server.sessions[session] = "/workspace"
	request := acpLine(1, "session/prompt", map[string]any{"sessionId": session, "prompt": []map[string]any{{"type": "text", "text": "status"}}})
	var output bytes.Buffer
	if err := server.Serve(context.Background(), bytes.NewReader(request), &output); err != nil {
		t.Fatalf("valid diagnostics broke transport: %v", err)
	}
	messages := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(messages) != 2 || !bytes.Contains(messages[0], []byte(receipt.Identity())) || !bytes.Contains(messages[0], []byte("omitted")) || !bytes.Contains(messages[1], []byte(`"stopReason":"end_turn"`)) {
		t.Fatalf("missing bounded response: messages=%d", len(messages))
	}
	for _, message := range messages {
		if len(message)+1 > maxACPMessageBytes {
			t.Fatal("oversized frame emitted")
		}
	}
	output.Reset()
	if err := server.Serve(context.Background(), bytes.NewReader(acpLine(2, "unknown", map[string]any{})), &output); err != nil || output.Len() == 0 {
		t.Fatalf("subsequent request failed: %v", err)
	}
}

type cancelDuringDiagnostics struct {
	receipt controlplane.ReviewRunReceipt
	started chan struct{}
}

func (s *cancelDuringDiagnostics) GetRun(context.Context, audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	return s.receipt, nil
}
func (s *cancelDuringDiagnostics) GetDiagnosticSet(ctx context.Context, _ audit.ReviewScope) (diagnostics.Set, error) {
	close(s.started)
	<-ctx.Done()
	return diagnostics.Set{}, ctx.Err()
}

func TestServeCancellationDuringDiagnosticRead(t *testing.T) {
	scope, receipt, _ := acpFixture(t)
	service := &cancelDuringDiagnostics{receipt: receipt, started: make(chan struct{})}
	server, err := New(service, scope)
	if err != nil {
		t.Fatal(err)
	}
	server.initialized = true
	session := strings.Repeat("a", 32)
	server.sessions[session] = "/workspace"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, reader, &output) }()
	request := acpLine(1, "session/prompt", map[string]any{"sessionId": session, "prompt": []map[string]any{{"type": "text", "text": "status"}}})
	if _, err := writer.Write(request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-service.started:
	case <-ctx.Done():
		t.Fatal("diagnostic read did not start")
	}
	notification := []byte(`{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"` + session + `"}}` + "\n")
	if _, err := writer.Write(notification); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("cancellation did not finish")
	}
	if !bytes.Contains(output.Bytes(), []byte(`"stopReason":"cancelled"`)) || bytes.Contains(output.Bytes(), []byte(`"method":"session/update"`)) {
		t.Fatalf("cancellation emitted normal result: %s", output.Bytes())
	}
}
