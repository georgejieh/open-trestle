package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/webhook"
)

type refusingReader struct {
	readerStub
	record webhook.RefusalRecord
}

func (r *refusingReader) GetRun(context.Context, audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	return controlplane.ReviewRunReceipt{}, errors.New("not found")
}
func (r *refusingReader) GetDeliveryRefusal(_ context.Context, scope audit.ReviewScope) (webhook.RefusalRecord, error) {
	if scope.ReviewRunID() != "webhook-"+r.record.DeduplicationKey() {
		return webhook.RefusalRecord{}, errors.New("not found")
	}
	return r.record, nil
}

// run_status reports a refused delivery with its fixed reason and the
// content-free refusal record instead of a bare read failure.
func TestRunStatusReportsADeliveryRefusal(t *testing.T) {
	repositoryScope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	delivery, _ := webhook.NewVerifiedDelivery(repositoryScope, webhook.SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"secret":"payload"}`), time.UnixMilli(1000))
	stored, _ := webhook.NewStoredDelivery(delivery, time.UnixMilli(1000))
	record, err := webhook.NewRefusalRecord(stored, strings.Repeat("d", 64), webhook.RefusalReasonRetriesExhausted, time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(&refusingReader{record: record})
	if err != nil {
		t.Fatal(err)
	}
	call := func(run string) string {
		var input, output bytes.Buffer
		input.Write(requestLine(1, "tools/call", map[string]any{"_meta": requestMeta(), "name": "open_trestle.run_status", "arguments": map[string]any{"tenant_id": "tenant-a", "repository_id": "repo-a", "review_run_id": run}}))
		if err := server.Serve(context.Background(), &input, &output); err != nil {
			t.Fatal(err)
		}
		var response struct {
			Result struct {
				IsError bool `json:"isError"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &response); err != nil || !response.Result.IsError || len(response.Result.Content) != 1 {
			t.Fatalf("response=%s err=%v", output.String(), err)
		}
		return response.Result.Content[0].Text
	}
	text := call(webhook.ReviewRunIDForDelivery(delivery))
	encoded, _ := webhook.EncodeRefusalRecord(record)
	if !strings.Contains(text, "intake refused this delivery: retries_exhausted ("+webhook.RefusalExplanation(webhook.RefusalReasonRetriesExhausted)+")") || !strings.Contains(text, string(encoded)) || strings.Contains(text, "secret") {
		t.Fatalf("refusal text=%s", text)
	}
	if other := call("webhook-" + strings.Repeat("b", 64)); other != "The review run could not be read." {
		t.Fatalf("missing run text=%s", other)
	}
}
