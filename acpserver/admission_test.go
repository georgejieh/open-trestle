package acpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

func TestPromptAdmissionHasGlobalBound(t *testing.T) {
	scope, receipt, set := acpFixture(t)
	server, err := New(&serviceStub{receipt: receipt, set: set}, scope)
	if err != nil {
		t.Fatal(err)
	}
	server.initialized = true
	admitted := 0
	for i := 0; i < maxACPSessions; i++ {
		session := fmt.Sprintf("%032x", i+1)
		server.sessions[session] = "/workspace"
		_, cancel := context.WithCancel(context.Background())
		defer cancel()
		if server.beginPrompt(session, cancel) {
			admitted++
		}
	}
	if admitted > 8 {
		t.Fatalf("unbounded prompt admission: %d", admitted)
	}
}

type heldACPOutput struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *heldACPOutput) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}

func TestPromptAdmissionHeldUntilOutputCompletes(t *testing.T) {
	scope, receipt, set := acpFixture(t)
	server, err := New(&serviceStub{receipt: receipt, set: set}, scope)
	if err != nil {
		t.Fatal(err)
	}
	server.initialized = true
	session := fmt.Sprintf("%032x", 1)
	server.sessions[session] = "/workspace"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	sink := &heldACPOutput{entered: make(chan struct{}), release: make(chan struct{})}
	var released sync.Once
	release := func() { released.Do(func() { close(sink.release) }) }
	defer release()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, input, sink) }()
	request := acpLine(1, "session/prompt", map[string]any{"sessionId": session, "prompt": []map[string]any{{"type": "text", "text": "status"}}})
	if _, err := writer.Write(request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sink.entered:
	case <-ctx.Done():
		t.Fatal("output did not start")
	}
	server.mu.Lock()
	_, reserved := server.active[session]
	server.mu.Unlock()
	release()
	writer.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("server did not finish")
	}
	if !reserved {
		t.Fatal("prompt admission released before blocked output finished")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.active) != 0 {
		t.Fatal("finished prompt retained admission")
	}
}

func TestPromptAdmissionRejectsUnknownSession(t *testing.T) {
	scope, receipt, set := acpFixture(t)
	service := &serviceStub{receipt: receipt, set: set}
	server, err := New(service, scope)
	if err != nil {
		t.Fatal(err)
	}
	server.initialized = true
	request := rpcRequest{ID: json.RawMessage("1"), Params: json.RawMessage(`{"sessionId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","prompt":[{"type":"text","text":"status"}]}`)}
	if messages := server.prompt(context.Background(), request); len(messages) != 1 {
		t.Fatal("missing rejection")
	}
	if service.runCalls != 0 || service.diagnosticCalls != 0 || len(server.active) != 0 {
		t.Fatal("unknown session admitted backend work")
	}
}

func TestCancellationRemainsAvailableAtPromptCapacity(t *testing.T) {
	scope, receipt, set := acpFixture(t)
	server, err := New(&serviceStub{receipt: receipt, set: set}, scope)
	if err != nil {
		t.Fatal(err)
	}
	server.initialized = true
	contexts := make([]context.Context, 0, maxActivePrompts)
	for i := 0; i < maxActivePrompts; i++ {
		id := fmt.Sprintf("%032x", i+1)
		server.sessions[id] = "/workspace"
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if !server.beginPrompt(id, cancel) {
			t.Fatal("prompt not admitted")
		}
		contexts = append(contexts, ctx)
	}
	session := fmt.Sprintf("%032x", 1)
	server.cancelSession([]byte(`{"sessionId":"` + session + `"}`))
	if contexts[0].Err() != context.Canceled {
		t.Fatal("capacity prevented cancellation")
	}
	if server.beginPrompt(session, func() {}) {
		t.Fatal("cancellation prematurely freed pending output slot")
	}
	server.endPrompt(session)
	if !server.beginPrompt(session, func() {}) {
		t.Fatal("completed prompt did not free slot")
	}
}
