package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/testsupport"
)

// failedReceiptWithReason is a failed run's receipt v3: its source task
// recorded no_merge_base.
func failedReceiptWithReason(t *testing.T) controlplane.ReviewRunReceipt {
	t.Helper()
	ctx := context.Background()
	at := time.UnixMilli(1000)
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	source, err := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("d", 64), nil, 1, 1000, 30000, true)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{source})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	if _, err := coordinator.Open(ctx, plan, at); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Advance(ctx, plan, at); err != nil {
		t.Fatal(err)
	}
	lease, claimed, err := coordinator.ClaimTask(ctx, plan, "source", source.HandlerIdentity(), "worker-a", at)
	if err != nil || !claimed {
		t.Fatalf("claim: %v", err)
	}
	completion, err := controlplane.NewSourceTaskFailureWithReason(controlplane.RunFailureInvalidInput, controlplane.TaskFailureReasonNoMergeBase, plan, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, at); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.FailRun(ctx, plan, controlplane.RunFailureInvalidInput, at); err != nil {
		t.Fatal(err)
	}
	receipt, err := coordinator.Receipt(ctx, scope)
	if err != nil || receiptVersion(t, receipt) != 3 {
		t.Fatalf("fixture is not receipt v3: %v", err)
	}
	return receipt
}

func receiptVersion(t *testing.T, receipt controlplane.ReviewRunReceipt) int {
	t.Helper()
	encoded, err := controlplane.EncodeReviewRunReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(encoded, &header); err != nil {
		t.Fatal(err)
	}
	return header.SchemaVersion
}

// matchesOutputSchema checks structured content against the closed keywords
// a tool output schema declares: required members and each member's const,
// enum, and pattern.
func matchesOutputSchema(schema map[string]any, value map[string]any) bool {
	for _, name := range schema["required"].([]any) {
		if _, present := value[name.(string)]; !present {
			return false
		}
	}
	for name, raw := range schema["properties"].(map[string]any) {
		property, member := raw.(map[string]any), value[name]
		if expected, ok := property["const"]; ok && !reflect.DeepEqual(expected, member) {
			return false
		}
		if values, ok := property["enum"].([]any); ok {
			found := false
			for _, candidate := range values {
				found = found || reflect.DeepEqual(candidate, member)
			}
			if !found {
				return false
			}
		}
		if pattern, ok := property["pattern"].(string); ok {
			text, isText := member.(string)
			if !isText || !regexp.MustCompile(pattern).MatchString(text) {
				return false
			}
		}
	}
	return true
}

// A receipt tool's structured content matches the output schema it declares,
// for the receipt v3 of a failed run with a failure reason as for v1, and
// carries a model task's provider refusal reason unchanged.
func TestReceiptToolsDeclareEveryReceiptVersion(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	refused, err := testsupport.ProviderRefusalReceipt(scope, controlplane.TaskFailureReasonProviderPaymentRequired)
	if err != nil {
		t.Fatal(err)
	}
	unaccepted, err := testsupport.ProviderRefusalReceipt(scope, controlplane.TaskFailureReasonProviderResponseInvalid)
	if err != nil {
		t.Fatal(err)
	}
	invalidAnswer, err := testsupport.ProviderRefusalReceipt(scope, controlplane.TaskFailureReasonModelOutputInvalid)
	if err != nil {
		t.Fatal(err)
	}
	for _, receipt := range []controlplane.ReviewRunReceipt{mcpReceipt(t), failedReceiptWithReason(t), refused, unaccepted, invalidAnswer} {
		server, err := New(&readerStub{receipt: receipt})
		if err != nil {
			t.Fatal(err)
		}
		var input, output bytes.Buffer
		input.Write(requestLine(1, "tools/list", map[string]any{"_meta": requestMeta()}))
		input.Write(requestLine(2, "tools/call", map[string]any{"_meta": requestMeta(), "name": "open_trestle.run_status", "arguments": map[string]any{"tenant_id": "tenant-a", "repository_id": "repo-a", "review_run_id": "run-a"}}))
		if err := server.Serve(context.Background(), &input, &output); err != nil {
			t.Fatal(err)
		}
		lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
		var list struct {
			Result struct {
				Tools []struct {
					Name         string         `json:"name"`
					OutputSchema map[string]any `json:"outputSchema"`
				} `json:"tools"`
			} `json:"result"`
		}
		var call struct {
			Result struct {
				Structured map[string]any `json:"structuredContent"`
			} `json:"result"`
		}
		if len(lines) != 2 || json.Unmarshal(lines[0], &list) != nil || json.Unmarshal(lines[1], &call) != nil || call.Result.Structured == nil {
			t.Fatalf("output=%s", output.String())
		}
		for _, tool := range list.Result.Tools {
			if tool.OutputSchema != nil && !matchesOutputSchema(tool.OutputSchema, call.Result.Structured) {
				t.Errorf("%s does not declare receipt v%d", tool.Name, receiptVersion(t, receipt))
			}
		}
		if receipt.Identity() == refused.Identity() && !bytes.Contains(lines[1], []byte(`"failure_reason":"provider_payment_required"`)) {
			t.Errorf("the status tool dropped the provider refusal: %s", lines[1])
		}
		if receipt.Identity() == unaccepted.Identity() && !bytes.Contains(lines[1], []byte(`"failure_reason":"provider_response_invalid"`)) {
			t.Errorf("the status tool dropped the refused provider reply: %s", lines[1])
		}
		if receipt.Identity() == invalidAnswer.Identity() && !bytes.Contains(lines[1], []byte(`"failure_reason":"model_output_invalid"`)) {
			t.Errorf("the status tool dropped the invalid model answer: %s", lines[1])
		}
	}
}
