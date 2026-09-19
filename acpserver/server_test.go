package acpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"strings"
	"sync"
	"testing"
	"time"
)

type serviceStub struct {
	receipt                   controlplane.ReviewRunReceipt
	set                       diagnostics.Set
	runCalls, diagnosticCalls int
}

func (s *serviceStub) GetRun(context.Context, audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	s.runCalls++
	return s.receipt, nil
}
func (s *serviceStub) GetDiagnosticSet(context.Context, audit.ReviewScope) (diagnostics.Set, error) {
	s.diagnosticCalls++
	return s.set, nil
}
func acpFixture(t *testing.T) (audit.ReviewScope, controlplane.ReviewRunReceipt, diagnostics.Set) {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	state, _ := coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	receipt, _ := controlplane.NewReviewRunReceipt(state)
	omission, _ := diagnostics.NewOmissionSummary(diagnostics.OmissionSelectionLimit, 1)
	check, _ := diagnostics.NewDeterministicCheck("3f01f93e51003eb3a0deca04719a3957d6e367c97c33bdfea105174d95698092", strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckPassed, 1, 2, 1, 2, 0)
	set, _ := diagnostics.NewSetWithDeterministicChecks(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64), 0, 0, 0, 2, 1, 1, []diagnostics.OmissionSummary{omission}, []diagnostics.DeterministicCheck{check}, nil)
	return scope, receipt, set
}
func acpLine(id int, method string, params any) []byte {
	encoded, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return append(encoded, '\n')
}
func TestServerInitializesCreatesSessionAndReportsVerifiedState(t *testing.T) {
	scope, receipt, set := acpFixture(t)
	service := &serviceStub{receipt: receipt, set: set}
	server, err := New(service, scope)
	if err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	input.Write(acpLine(1, "initialize", map[string]any{"protocolVersion": 1, "clientCapabilities": map[string]any{}}))
	input.Write(acpLine(2, "session/new", map[string]any{"cwd": "/workspace", "mcpServers": []any{}}))
	var firstOutput bytes.Buffer
	if err := server.Serve(context.Background(), &input, &firstOutput); err != nil {
		t.Fatal(err)
	}
	responses := bytes.Split(bytes.TrimSpace(firstOutput.Bytes()), []byte{'\n'})
	if len(responses) != 2 {
		t.Fatalf("responses=%d output=%s", len(responses), firstOutput.String())
	}
	var newSession struct {
		Result struct {
			SessionID string `json:"sessionId"`
		} `json:"result"`
	}
	if err := json.Unmarshal(responses[1], &newSession); err != nil || newSession.Result.SessionID == "" {
		t.Fatalf("session=(%#v,%v)", newSession, err)
	}
	prompt := acpLine(3, "session/prompt", map[string]any{"sessionId": newSession.Result.SessionID, "prompt": []map[string]any{{"type": "text", "text": "Show review status"}}})
	var promptOutput bytes.Buffer
	if err := server.Serve(context.Background(), bytes.NewReader(prompt), &promptOutput); err != nil {
		t.Fatal(err)
	}
	messages := bytes.Split(bytes.TrimSpace(promptOutput.Bytes()), []byte{'\n'})
	if len(messages) != 2 || service.runCalls != 1 || service.diagnosticCalls != 1 {
		t.Fatalf("messages=%d calls=(%d,%d) output=%s", len(messages), service.runCalls, service.diagnosticCalls, promptOutput.String())
	}
	if !bytes.Contains(messages[0], []byte(`"method":"session/update"`)) || !bytes.Contains(messages[0], []byte(receipt.Identity())) || !bytes.Contains(messages[0], []byte(set.Identity())) || !bytes.Contains(messages[0], []byte(`source_coverage`)) || !bytes.Contains(messages[0], []byte(`selection_limit`)) || !bytes.Contains(messages[0], []byte(`static_debug_output`)) || !bytes.Contains(messages[0], []byte("untrusted")) {
		t.Fatalf("update=%s", messages[0])
	}
	if !bytes.Contains(messages[1], []byte(`"stopReason":"end_turn"`)) {
		t.Fatalf("response=%s", messages[1])
	}
}
func TestServerRejectsFilesystemAndMCPExpansion(t *testing.T) {
	scope, receipt, set := acpFixture(t)
	server, _ := New(&serviceStub{receipt: receipt, set: set}, scope)
	requests := [][]byte{acpLine(1, "session/new", map[string]any{"cwd": "relative", "mcpServers": []any{}}), acpLine(2, "session/new", map[string]any{"cwd": "/workspace", "mcpServers": []any{map[string]any{"name": "untrusted"}}})}
	for _, request := range requests {
		var output bytes.Buffer
		if err := server.Serve(context.Background(), bytes.NewReader(request), &output); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(output.Bytes(), []byte(`"error"`)) {
			t.Fatalf("output=%s", output.String())
		}
	}
}

type cancelService struct {
	started chan struct{}
	once    sync.Once
}

func (s *cancelService) GetRun(ctx context.Context, _ audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	s.once.Do(func() { close(s.started) })
	<-ctx.Done()
	return controlplane.ReviewRunReceipt{}, ctx.Err()
}
func (s *cancelService) GetDiagnosticSet(context.Context, audit.ReviewScope) (diagnostics.Set, error) {
	return diagnostics.Set{}, errors.New("unavailable")
}
func TestServerCancellationStopsActivePrompt(t *testing.T) {
	scope, _, _ := acpFixture(t)
	service := &cancelService{started: make(chan struct{})}
	server, _ := New(service, scope)
	_ = server.initialize(rpcRequest{ID: json.RawMessage("1"), Params: json.RawMessage(`{"protocolVersion":1,"clientCapabilities":{}}`)})
	sessionResponse := server.newSession(rpcRequest{ID: json.RawMessage("2"), Params: json.RawMessage(`{"cwd":"/workspace","mcpServers":[]}`)})
	encoded, _ := json.Marshal(sessionResponse)
	var response struct {
		Result struct {
			SessionID string `json:"sessionId"`
		} `json:"result"`
	}
	_ = json.Unmarshal(encoded, &response)
	promptRequest := rpcRequest{ID: json.RawMessage("3"), Params: json.RawMessage(`{"sessionId":"` + response.Result.SessionID + `","prompt":[{"type":"text","text":"status"}]}`)}
	done := make(chan []any, 1)
	go func() { done <- server.prompt(context.Background(), promptRequest) }()
	<-service.started
	server.cancelSession([]byte(`{"sessionId":"` + response.Result.SessionID + `"}`))
	messages := <-done
	encoded, _ = json.Marshal(messages)
	if !bytes.Contains(encoded, []byte(`"stopReason":"cancelled"`)) {
		t.Fatalf("messages=%s", encoded)
	}
}
