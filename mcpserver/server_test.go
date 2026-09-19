package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"strings"
	"testing"
	"time"
)

type readerStub struct {
	receipt controlplane.ReviewRunReceipt
	calls   int
}

func (r *readerStub) GetRun(context.Context, audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	r.calls++
	return r.receipt, nil
}
func (r *readerStub) SubmitRun(context.Context, controlplane.ReviewRunPlan) (controlplane.ReviewRunReceipt, error) {
	r.calls++
	return r.receipt, nil
}
func mcpReceipt(t *testing.T) controlplane.ReviewRunReceipt {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	state, _ := coordinator.Open(context.Background(), plan, time.UnixMilli(100))
	receipt, _ := controlplane.NewReviewRunReceipt(state)
	return receipt
}
func requestLine(id int, method string, params any) []byte {
	encoded, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return append(encoded, '\n')
}
func requestMeta() map[string]any {
	return map[string]any{"io.modelcontextprotocol/protocolVersion": ProtocolVersion, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
}
func TestServerDiscoversListsAndCallsReadOnlyStatusTool(t *testing.T) {
	reader := &readerStub{receipt: mcpReceipt(t)}
	server, err := New(reader)
	if err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	input.Write(requestLine(1, "server/discover", map[string]any{"_meta": requestMeta()}))
	input.Write(requestLine(2, "tools/list", map[string]any{"_meta": requestMeta()}))
	input.Write(requestLine(3, "tools/call", map[string]any{"_meta": requestMeta(), "name": "open_trestle.run_status", "arguments": map[string]any{"tenant_id": "tenant-a", "repository_id": "repo-a", "review_run_id": "run-a"}}))
	var output bytes.Buffer
	if err := server.Serve(context.Background(), &input, &output); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
	if len(lines) != 3 || reader.calls != 1 {
		t.Fatalf("lines=%d calls=%d output=%s", len(lines), reader.calls, output.String())
	}
	var discover map[string]any
	if err := json.Unmarshal(lines[0], &discover); err != nil {
		t.Fatal(err)
	}
	result := discover["result"].(map[string]any)
	if result["resultType"] != "complete" {
		t.Fatalf("discover=%#v", discover)
	}
	var call struct {
		Result struct {
			IsError    bool            `json:"isError"`
			Structured json.RawMessage `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(lines[2], &call); err != nil || call.Result.IsError {
		t.Fatalf("call=(%#v,%v)", call, err)
	}
	var structured struct {
		Identity string `json:"identity"`
		Contract string `json:"contract"`
	}
	if err := json.Unmarshal(call.Result.Structured, &structured); err != nil || structured.Identity != reader.receipt.Identity() || structured.Contract != "open-trestle/review-run-receipt" {
		t.Fatalf("structured=(%#v,%v)", structured, err)
	}
}
func TestServerRejectsMissingOrUnsupportedRequestMetadata(t *testing.T) {
	reader := &readerStub{receipt: mcpReceipt(t)}
	server, _ := New(reader)
	tests := [][]byte{requestLine(1, "tools/list", map[string]any{}), requestLine(2, "tools/list", map[string]any{"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": "old", "io.modelcontextprotocol/clientCapabilities": map[string]any{}}})}
	for _, input := range tests {
		var output bytes.Buffer
		if err := server.Serve(context.Background(), bytes.NewReader(input), &output); err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(output.Bytes(), []byte(`"error"`)) {
			t.Fatalf("output=%s", output.String())
		}
	}
}

func TestServerDoesNotRespondToCancellationNotification(t *testing.T) {
	server, _ := New(&readerStub{receipt: mcpReceipt(t)})
	notification, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"_meta": requestMeta(), "requestId": 1}})
	notification = append(notification, '\n')
	var output bytes.Buffer
	if err := server.Serve(context.Background(), bytes.NewReader(notification), &output); err != nil || output.Len() != 0 {
		t.Fatalf("serve=(%v,%q)", err, output.String())
	}
}

func TestServerSubmitsCanonicalPlanWithoutPublicationAuthority(t *testing.T) {
	receipt := mcpReceipt(t)
	service := &readerStub{receipt: receipt}
	server, _ := New(service)
	scope := receipt.Scope()
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	encoded, _ := controlplane.EncodeReviewRunPlan(plan)
	input := requestLine(4, "tools/call", map[string]any{"_meta": requestMeta(), "name": "open_trestle.submit_run", "arguments": map[string]any{"plan_json": string(encoded)}})
	var output bytes.Buffer
	if err := server.Serve(context.Background(), bytes.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if service.calls != 1 || !bytes.Contains(output.Bytes(), []byte(`"isError":false`)) {
		t.Fatalf("calls=%d output=%s", service.calls, output.String())
	}
}

func TestServerRejectsCrossWiredServiceReceipts(t *testing.T) {
	receipt := mcpReceipt(t)
	task, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, scopeParts := range [][3]string{{"tenant-b", "repo-a", "run-a"}, {"tenant-a", "repo-b", "run-a"}, {"tenant-a", "repo-a", "run-b"}, {"tenant-a", "repo-a", "run-a"}} {
		scope, err := audit.NewReviewScope(scopeParts[0], scopeParts[1], scopeParts[2])
		if err != nil {
			t.Fatal(err)
		}
		plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("f", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
		if err != nil {
			t.Fatal(err)
		}
		encodedPlan, err := controlplane.EncodeReviewRunPlan(plan)
		if err != nil {
			t.Fatal(err)
		}
		for _, operation := range []string{"status", "submit"} {
			if operation == "status" && scope.Identity() == receipt.Scope().Identity() {
				continue
			}
			t.Run(operation+"/"+strings.Join(scopeParts[:], "/"), func(t *testing.T) {
				service := &readerStub{receipt: receipt}
				server, err := New(service)
				if err != nil {
					t.Fatal(err)
				}
				name := "open_trestle.run_status"
				arguments := map[string]any{"tenant_id": scopeParts[0], "repository_id": scopeParts[1], "review_run_id": scopeParts[2]}
				if operation == "submit" {
					name = "open_trestle.submit_run"
					arguments = map[string]any{"plan_json": string(encodedPlan)}
				}
				input := requestLine(10, "tools/call", map[string]any{"_meta": requestMeta(), "name": name, "arguments": arguments})
				var output bytes.Buffer
				if err := server.Serve(context.Background(), bytes.NewReader(input), &output); err != nil {
					t.Fatal(err)
				}
				var response struct {
					Result struct {
						IsError    bool            `json:"isError"`
						Structured json.RawMessage `json:"structuredContent"`
					} `json:"result"`
				}
				if err := json.Unmarshal(output.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if !response.Result.IsError || len(response.Result.Structured) != 0 || bytes.Contains(output.Bytes(), []byte(receipt.Identity())) {
					t.Fatalf("cross-wired receipt forwarded: %s", output.Bytes())
				}
			})
		}
	}
}
