package acpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/webhook"
)

type refusingService struct {
	serviceStub
	record webhook.RefusalRecord
	runErr error
}

func (s *refusingService) GetRun(context.Context, audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	return controlplane.ReviewRunReceipt{}, s.runErr
}
func (s *refusingService) GetDeliveryRefusal(context.Context, audit.ReviewScope) (webhook.RefusalRecord, error) {
	return s.record, nil
}

// The review-state prompt reports a refused delivery with its fixed reason
// and content-free record instead of "Review status is unavailable." when the
// run is not found, and keeps reporting any other read failure as such.
func TestPromptReportsADeliveryRefusal(t *testing.T) {
	repositoryScope, _ := webhook.NewRepositoryScope("tenant-a", "repo-a")
	delivery, _ := webhook.NewVerifiedDelivery(repositoryScope, webhook.SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"secret":"payload"}`), time.UnixMilli(1000))
	stored, _ := webhook.NewStoredDelivery(delivery, time.UnixMilli(1000))
	record, err := webhook.NewRefusalRecord(stored, strings.Repeat("d", 64), "invalid_pull_request_payload", time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", webhook.ReviewRunIDForDelivery(delivery))
	prompt := func(runErr error) string {
		server, err := New(&refusingService{record: record, runErr: runErr}, scope)
		if err != nil {
			t.Fatal(err)
		}
		var input, output bytes.Buffer
		input.Write(acpLine(1, "initialize", map[string]any{"protocolVersion": 1, "clientCapabilities": map[string]any{}}))
		input.Write(acpLine(2, "session/new", map[string]any{"cwd": "/workspace", "mcpServers": []any{}}))
		if err := server.Serve(context.Background(), &input, &output); err != nil {
			t.Fatal(err)
		}
		var session struct {
			Result struct {
				SessionID string `json:"sessionId"`
			} `json:"result"`
		}
		lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'})
		if err := json.Unmarshal(lines[len(lines)-1], &session); err != nil || session.Result.SessionID == "" {
			t.Fatalf("session: %v", err)
		}
		var promptOutput bytes.Buffer
		request := acpLine(3, "session/prompt", map[string]any{"sessionId": session.Result.SessionID, "prompt": []map[string]any{{"type": "text", "text": "Show review status"}}})
		if err := server.Serve(context.Background(), bytes.NewReader(request), &promptOutput); err != nil {
			t.Fatal(err)
		}
		return promptOutput.String()
	}
	text := prompt(fmt.Errorf("read run: %w", controlplane.ErrRunNotOpened))
	if !strings.Contains(text, "intake refused this delivery: invalid_pull_request_payload") || !strings.Contains(text, record.Identity()) || strings.Contains(text, "secret") || strings.Contains(text, "Review status is unavailable") {
		t.Fatalf("prompt output=%s", text)
	}
	if text := prompt(errors.New("daemon unavailable")); !strings.Contains(text, "Review status is unavailable.") || strings.Contains(text, "intake refused") {
		t.Fatalf("a transient read failure was reported as a refusal: %s", text)
	}
}
